# Windows-Analysis

수집된 Windows 아티팩트(레지스트리 하이브, 이벤트 로그, 브라우저 DB, 점프리스트 등)를 분석하기 쉬운 `.csv`로 일괄 변환하는 파이썬 툴입니다. Eric Zimmerman's Tools와 비슷한 목적이지만, 하나의 파이프라인(`main.py`)에서 여러 아티팩트를 한 번에 처리하도록 만들었습니다.

## 요구 사항

- Python 3.12
- Windows (레지스트리 하이브·`.lnk`/점프리스트 파싱 대상이 Windows 아티팩트이므로 Windows 환경 기준으로 개발/테스트함)

## 설치

```powershell
py -3.12 -m virtualenv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## 실행

```powershell
python main.py --target target --output result
```

- `--target`: 수집된 아티팩트가 들어있는 루트 폴더 (기본값 `target/`)
- `--output`: 결과 CSV를 저장할 루트 폴더 (기본값 `result/`)

실행하면 등록된 아티팩트를 순서대로 찾아서 파싱하고, `result/<카테고리>/*.csv`로 저장합니다.

## 파싱 기준 (공통 규칙)

이 프로젝트 전체에 걸쳐 지키는 규칙입니다. 새 파서를 추가할 때도 이 규칙을 따릅니다.

### 1. 파일은 폴더 구조가 아니라 파일명/확장자/내용으로 찾는다

수집기가 만든 `target/` 폴더 구조는 신뢰하지 않습니다. 아티팩트는 다음 세 가지 방식 중 하나로 탐색합니다 (`common/finder.py`):

- **파일명**: `find_files_by_name()` — 예) Amcache.hve, History, Login Data (대소문자 무시, 정확히 일치)
- **확장자**: `find_files_by_extension()` — 예) `.evtx`, `.automaticDestinations-ms`
- **내용(매직 바이트)**: `find_sqlite_files()` — 파일명이 제각각인 SQLite DB를 헤더 바이트로 판별

예외적으로 브라우저 관련 SQLite 덤프는 `find_sqlite_files(..., under_folder="BROWSER")`처럼 특정 폴더 하위로 범위를 좁히기도 하는데, 이건 "찾는" 기준이 아니라 수집기가 이미 분류해둔 폴더를 신뢰하는 것으로 별개입니다 — 브라우저 이름(`common/browser_id.py`)처럼 "이미 찾은 파일에 라벨 붙이기"에도 폴더 구조를 활용하지만, 파일을 하드코딩된 이름 목록으로 찾지는 않습니다.

같은 파일이 수집기에 의해 여러 폴더에 중복 저장된 경우(예: JumpList가 `JUMPLIST/`와 `LNK/Recent/`에 동시에 존재), `common/finder.dedupe_by_content()`가 SHA-256 기준으로 중복을 제거합니다. `main.py`에서 모든 아티팩트에 공통 적용됩니다.

### 2. 시간 값은 항상 맨 앞 컬럼, `YYYY-MM-DD hh:mm:ss.fff`, KST(+9) 고정

`common/utils.py`의 `format_timestamp(value, source_tz)` 규칙:

- 포맷은 항상 `YYYY-MM-DD hh:mm:ss.fff` (밀리초 없으면 `.000`)
- 항상 UTC+9(KST)로 변환해서 출력
- **naive(타임존 정보 없는) 값을 무조건 UTC로 가정하지 않습니다.** `source_tz`는 필수 인자이며, 호출하는 쪽(각 파서)이 "이 필드가 실제로 어떤 타임존인지"를 근거와 함께 확인한 뒤 명시적으로 넘겨야 합니다. 이미 타임존 정보가 있는 값(예: ISO8601 `+00:00`)은 그 정보를 그대로 존중합니다.
- Chromium 계열(브라우저) 타임스탬프는 `common/chrome_time.py`의 `chrome_timestamp()`를 통해 별도로 처리합니다 (1601-01-01 기준 마이크로초, UTC 확정).

각 파서 상단 주석에 "왜 이 필드를 UTC로 보는지"에 대한 근거를 남겨둡니다 (예: Amcache의 `LinkDate`는 naive 문자열이지만 PE 헤더 빌드 시각 특성상 UTC, EZ의 AmcacheParser 소스로 교차 검증함).

### 3. 깨진 데이터는 숨기지 않고 그대로 보여준다

파싱에 실패한 레코드/청크/파일은 조용히 건너뛰지 않고, `_status`/`_error` 컬럼이 있는 행으로 결과에 남깁니다 (예: EventLog의 `corrupted_chunk`, JumpList의 `corrupted`, SQLite 파서들의 `*_Errors.csv`). Microsoft Message Analyzer처럼 손상된 파일을 통째로 안 보여주는 대신, EZ 도구처럼 "여기가 깨져있다"는 흔적을 남기는 쪽을 택했습니다.

### 4. 결과는 카테고리 폴더로 묶는다

`result/<CATEGORY>/*.csv` 구조입니다. 여러 파서가 같은 카테고리를 공유할 수 있습니다 (예: `BrowserHistory`, `BrowserLoginData`, SQLite 브라우저 덤프가 전부 `result/BROWSER/`로 모임). `common/registry.py`의 `ArtifactDefinition.category`로 지정합니다.

### 5. 원본 값을 함부로 추측해서 변환하지 않는다

값의 의미(예: 이 정수가 타임스탬프인지 카운터인지)를 확신할 수 없을 때는 원본 그대로 남겨둡니다. 예를 들어 범용 SQLite 덤프(`parsers/sqlite_generic_parser.py`)는 스코프가 확실히 Chromium 브라우저 DB로 좁혀져 있을 때만 컬럼명(`*_time`/`*_utc`/`*_date`) + 값 범위 휴리스틱으로 시간 변환을 시도하고, 그 외에는 원본 정수를 그대로 둡니다.

## 지원 아티팩트

| 아티팩트 | 파서 | 결과 폴더 | 비고 |
|---|---|---|---|
| Amcache | `parsers/amcache_parser.py` | `result/AMCACHE/` | Win10+ (`InventoryApplication(File)`)/구버전(`Root\Programs`,`Root\File`) 둘 다 지원. dirty hive 트랜잭션 로그(.LOG1/.LOG2) 자동 반영(`common/hive_recovery.py`). 삭제된(free) 레지스트리 셀 카빙으로 self-update 앱의 이전 버전 항목까지 일부 복구(`common/hbin_carver.py`) |
| EventLog | `parsers/eventlog_parser.py` | `result/EVENTLOG/` | `.evtx` 전부를 하나의 CSV로 병합. `evtx`(Rust 기반) 라이브러리로 손상된 청크도 스킵하지 않고 표시 |
| Browser - History | `parsers/browser_history_parser.py` | `result/BROWSER/` | Chromium 계열 `History` DB (urls/visits/downloads/keyword_search_terms) |
| Browser - Login Data | `parsers/browser_login_data_parser.py` | `result/BROWSER/` | `Login Data`/`Login Data For Account`의 `logins` 테이블. 암호화된 비밀번호 원문은 절대 읽지 않고 존재 여부만 기록 |
| Browser - SQLite 전체 | `parsers/sqlite_generic_parser.py` | `result/BROWSER/` | `BROWSER` 폴더 하위의 모든 Chromium SQLite DB(Cookies, Web Data, Favicons, Top Sites 등)를 테이블 단위로 전부 덤프. 전용 파서가 이미 다루는 테이블은 중복을 피하기 위해 제외 |
| JumpList | `parsers/jumplist_parser.py` | `result/JUMPLIST/` | `AutomaticDestinations-ms`(OLE + LNK) / `CustomDestinations-ms`(LNK 시그니처 스캔) 둘 다 지원. **DestList 자체(핀 고정/접근 횟수/MRU 순서)는 아직 파싱하지 않음** — LNK 헤더의 생성/접근/수정 시각과 타겟 경로까지만 |

### 알려진 범위 밖 항목

- IE `WebCacheV01.dat` (ESE/Jet Blue 포맷 — SQLite가 아니라 별도 파서 필요)
- Amcache의 삭제된 레지스트리 셀 카빙은 완전 복구된 레코드만 채택 (값 목록이 일부 덮어써진 경우는 조작해서 채우지 않고 버림)

## 새 아티팩트 파서 추가하기

1. `parsers/<이름>_parser.py`를 만들고 다음을 정의:
   - `ARTIFACT_NAME`: 로그에 표시될 이름
   - `FILENAMES` 또는 `EXTENSIONS`: 파일 탐색 기준 (내용 기반이 필요하면 `common/finder.py`에 새 `find_*` 함수 추가)
   - `FIELD_ORDER`: 출력 CSV별 컬럼 순서 (시간 컬럼이 항상 맨 앞에 오도록)
   - `parse(paths: list[Path]) -> dict[str, list[dict]]`: 결과 이름 → row 리스트
2. `common/registry.py`의 `ARTIFACTS` 리스트에 `ArtifactDefinition` 한 줄 추가 (`category`로 다른 아티팩트와 결과 폴더 공유 가능)
3. 시간 필드가 있다면 `common/utils.format_timestamp()` (또는 Chromium이면 `common/chrome_time.chrome_timestamp()`)로 변환하고, 그 필드가 왜 해당 타임존인지 근거를 주석으로 남길 것

## 프로젝트 구조

```
main.py                        진입점: 탐색 → 파싱 → 저장
common/
  finder.py                    파일 탐색 (이름/확장자/내용 기반), 중복 제거
  registry.py                  아티팩트 등록 목록
  csv_writer.py                dict 리스트 → CSV 저장
  utils.py                     공통 시간 포맷/변환 규칙
  chrome_time.py                Chromium epoch 시간 변환
  sqlite_utils.py               SQLite 읽기 전용 연결, 안전한 텍스트 디코딩
  browser_id.py                 경로에서 브라우저 이름 추출
  hive_recovery.py               레지스트리 하이브 트랜잭션 로그 반영
  hbin_carver.py                 삭제된 레지스트리 셀 카빙
parsers/
  amcache_parser.py
  eventlog_parser.py
  browser_history_parser.py
  browser_login_data_parser.py
  sqlite_generic_parser.py
  jumplist_parser.py
```
