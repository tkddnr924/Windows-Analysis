# Windows-Analysis

수집된 Windows 아티팩트(레지스트리 하이브, 이벤트 로그, 브라우저 DB/캐시, 점프리스트, 프리패치, SRUM, RDP 캐시 등)를 침해사고 분석에 쓰기 좋게 처리하는 DFIR 트리아지 툴입니다.

두 단계로 동작합니다.

1. **원본 파싱** — 각 아티팩트를 원본에 1:1로 대응하는 SQLite로 충실히 변환합니다. 값을 함부로 추측·가공하지 않고, 깨진 부분도 흔적을 남깁니다.
2. **가공(종합 분석)** — 여러 아티팩트를 교차 상관해 분석가가 실제로 보고 싶은 요약 테이블(`_OVERVIEW/`)을 만듭니다. 시스템/계정 개요, 실행 이력 통합, Defender 활동, 레지스트리 특이사항, RDP 세션, PowerShell 실행 등.

여기에 **Electron + Next.js 데스크톱 뷰어**가 붙어 있어, 파싱부터 분석까지 앱 안에서 케이스 단위로 진행합니다. GitHub Actions가 Windows 실행 파일(exe)을 빌드합니다.

> 이 저장소의 코드에는 특정 사건/조직/호스트에 종속된 값(IP·호스트명·계정명 등)을 하드코딩하지 않습니다. 모든 파서·상관 규칙은 Windows/포렌식 도메인의 일반 지식만 사용합니다.

## 요구 사항

- Python 3.12 (파이프라인)
- Node.js 20+ (뷰어)
- Windows 기준으로 개발/테스트 (레지스트리 하이브·`.evtx`·`.lnk` 등 Windows 아티팩트 대상). 파서 자체는 크로스플랫폼이지만 실사용은 Windows exe 뷰어로 합니다.

## 설치

```powershell
py -3.12 -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## 사용 방법

### 뷰어 (권장)

일반적인 사용은 뷰어 안에서 이루어집니다: **케이스 생성 → 호스트 추가(수집 폴더 지정) → 파싱 → 분석**. 파싱은 백그라운드에서 돌고, 화면을 옮겨도 진행 상태가 유지됩니다.

```powershell
cd viewer
npm install
npm run dev
```

빌드된 Windows exe는 GitHub Actions 아티팩트에서 받을 수 있습니다.

### CLI

뷰어 없이 파이프라인만 돌릴 수도 있습니다. 케이스/호스트 모델을 그대로 사용합니다.

```powershell
# 케이스 생성
python main.py --create-case "사건명"

# 호스트 등록 (수집 폴더 지정)
python main.py --create-host <CASE_ID> --name <호스트명> --target <수집폴더>

# 파싱 실행 (--only 로 일부 아티팩트만 재실행 가능)
python main.py --run-host <CASE_ID> --host <HOST_ID> [--only EventLog,Registry]

# 조회
python main.py --list-cases
python main.py --list-artifacts
```

결과는 `cases/<케이스>/<호스트>/` 아래에 저장됩니다:

- `cases/<케이스>/<호스트>/<CATEGORY>/*.sqlite` — 원본 파싱 결과 (원본 파일 1:1)
- `cases/<케이스>/<호스트>/_OVERVIEW/*.sqlite` — 가공·상관 분석 테이블

## 파싱 기준 (공통 규칙)

프로젝트 전체에 걸쳐 지키는 규칙입니다. 새 파서를 추가할 때도 따릅니다.

### 1. 파일은 폴더 구조가 아니라 파일명/확장자/내용으로 찾는다

수집기가 만든 폴더 구조는 신뢰하지 않습니다. 아티팩트는 다음 방식으로 탐색합니다 (`common/finder.py`).

- **파일명**: `find_files_by_name()` — 예) Amcache.hve, ConsoleHost_history.txt (대소문자 무시, 정확히 일치)
- **확장자**: `find_files_by_suffix()` — 예) `.evtx`, `.automaticDestinations-ms`
- **내용(매직 바이트)**: `find_files_by_content()` — 파일명이 제각각인 SQLite DB, RDP 캐시(`RDP8bmp`) 등을 헤더로 판별

같은 파일이 여러 폴더에 중복 저장된 경우 `dedupe_by_content()`가 SHA-256 기준으로 중복을 제거합니다 (`main.py`에서 모든 아티팩트에 공통 적용).

### 2. 시간 값은 항상 맨 앞 컬럼, `YYYY-MM-DD hh:mm:ss.fff`, KST(+9) 고정

`common/utils.format_timestamp(value, source_tz)` 규칙:

- 포맷은 항상 `YYYY-MM-DD hh:mm:ss.fff` (밀리초 없으면 `.000`), 문자열 비교가 곧 시간 순서가 되도록 고정 폭
- 항상 UTC+9(KST)로 변환해서 출력
- **naive(타임존 없는) 값을 무조건 UTC로 가정하지 않습니다.** `source_tz`는 필수 인자이며, 각 파서가 "이 필드가 실제로 어떤 타임존인지" 근거를 확인한 뒤 명시적으로 넘깁니다.
- Chromium 계열 타임스탬프는 `common/chrome_time.chrome_timestamp()`로 별도 처리 (1601 기준 마이크로초, UTC 확정)

### 3. 깨진 데이터는 숨기지 않고 그대로 보여준다

파싱에 실패한 레코드/청크/파일은 조용히 건너뛰지 않고 `_status`/`_error` 컬럼이 있는 행으로 남깁니다 (예: EventLog `corrupted_chunk`, 레지스트리 하이브 손상). 손상된 파일을 통째로 감추는 대신 "여기가 깨져있다"는 흔적을 남깁니다.

### 4. 원본 파싱은 원본과 1:1, SQLite로 저장

원본 아티팩트 하나당 SQLite 하나, 그 안의 구조(테이블) 하나당 테이블 하나로 저장합니다 (예: `SOFTWARE.sqlite` 안에 하이브의 모든 키/값을 담은 `Registry` 테이블). 이렇게 해야 원본을 그대로 재현할 수 있고, 상관 분석은 그 위에 별도 레이어로 얹습니다.

### 5. 원본 값을 함부로 추측해서 변환하지 않는다

값의 의미를 확신할 수 없으면(이 정수가 시간인지 카운터인지 등) 원본 그대로 둡니다. 대용량 컬럼이 폭증하지 않도록 SQLite 쓰기 계층(`common/sqlite_writer.py`)이 int64 범위를 벗어나는 값이나 스키마 과다 컬럼을 안전하게 처리합니다.

## 지원 아티팩트 (원본 파싱)

| 아티팩트 | 파서 | 카테고리 | 비고 |
|---|---|---|---|
| Amcache | `amcache_parser.py` | AMCACHE | Win10+/구버전 스키마 모두 지원. dirty hive 트랜잭션 로그(.LOG1/.LOG2) 자동 반영, 삭제된 셀 카빙으로 이전 버전 일부 복구 |
| Prefetch | `prefetch_parser.py` | PREFETCH | MAM 압축 `.pf` 처리, 최근 실행 시각·볼륨·로드 파일 |
| EventLog | `eventlog_parser.py` | EVENTLOG | `.evtx`를 소스별로 각각 한 테이블. 손상된 청크도 표시 |
| Registry | `registry_parser.py` | REGISTRY | SYSTEM/SOFTWARE/SAM/NTUSER 등 하이브별 전체 키/값 덤프(선별은 가공 레이어가 담당). 트랜잭션 로그 반영, RegBack 중복 제거 |
| UsnJrnl | `usnjrnl_parser.py` | FILESYSTEM | `$UsnJrnl:$J` 변경 저널 |
| JumpList | `jumplist_parser.py` | JUMPLIST | Automatic/Custom Destinations (OLE + LNK) |
| SRUM | `srum_parser.py` | SRUM | ESE DB — 앱/네트워크 사용량, 최초 관측 시각 |
| WER | `wer_parser.py` | WER | Windows 오류 보고(크래시/행) `.wer`. 인덱스형 키(LoadedModule 등)는 JSON 컬럼으로 접어 스키마 폭증 방지 |
| TaskScheduler | `taskscheduler_parser.py` | TASKSCHEDULER | 예약 작업 정의 XML |
| RdpCache | `rdpcache_parser.py` | RDPCACHE | RDP 비트맵 캐시 타일. 경계 픽셀 일치로 인접 타일을 이어붙여 화면 조각 복원(충돌 없는 배치·모호한 이음새 제외) |
| PowerShell | `powershell_history_parser.py` | POWERSHELL | ConsoleHost_history + Operational 로그 |
| Browser - History | `browser_history_parser.py` | BROWSER | Chromium History DB (방문/다운로드/검색어) |
| Browser - Cache | `browser_cache_parser.py` | BROWSER | Chromium blockfile 디스크 캐시(요청/응답 시각, URL) |

## 가공 · 종합 분석 (`_OVERVIEW/`)

원본 테이블 위에서 교차 상관해 만드는 요약 테이블입니다 (`common/processing.py`, `common/correlate.py`). 뷰어의 "종합 분석" 섹션에서 전용 화면으로 렌더링됩니다.

| 테이블 | 내용 |
|---|---|
| TargetInfo | 시스템 개요(OS/컴퓨터명/시간대/설치일/종료시각), 계정(SAM F레코드 RID 기반 — RID 하이재킹 탐지, 서비스 계정 포함), 네트워크 구성/연결 이력 |
| ExecutionHistory | Amcache·Prefetch·SRUM·AppCompatCache·BAM·UserAssist를 최초 관측 시각으로 통합한 실행 이력(위험 신호 태깅) |
| Defender | Windows Defender 이벤트 요약 — 탐지 위협·조치, 실시간 보호 해제/복원, 검사, 기록 삭제, 서명 버전 |
| RegistryFindings | 레지스트리 특이사항 — 자동 실행, 공유 폴더, 자격 증명 보호(WDigest/RunAsPPL), SQL 인증 모드 등 근거(키 경로·값) 중심 |
| BrowserActivity | 방문·다운로드·캐시를 시간순으로 통합한 브라우저 활동 |
| RemoteDesktopHistory | RDP 인바운드/아웃바운드 세션(Security·TerminalServices 로그), 성공/실패·계정 |
| PowerShellHistory | PowerShell 실행/스크립트 블록 활동 |
| RdpCache | RDP 비트맵 캐시에서 복원한 화면 조각(붙여진 데이터) |

## 뷰어 앱 (`viewer/`)

파싱과 분석을 케이스 단위로 진행하는 Electron + Next.js 데스크톱 앱입니다. 파이썬 파이프라인을 자식 프로세스로 실행하고 결과 SQLite를 읽습니다.

- **케이스 · 호스트 관리** — 사건(케이스) 아래 여러 호스트를 등록하고 앱에서 바로 파싱. 백그라운드로 돌아 화면 전환/재방문에도 진행 상태 유지.
- **케이스 분석** (사건 전체)
  - **호스트 연결** — 등록 호스트를 밝은 노드, 확인된 외부 IP를 어두운 노드로 그리는 force-directed 그래프. RDP 접속 방향(인바운드/아웃바운드), LOCAL(콘솔/AD 경유 가능성)·루프백(원격/터널링 도구 가능성) 구분, 드래그·줌·팬, 노드 클릭 상세, 간격 조절 패널, 등록/Local/로컬호스트 필터.
  - **북마크** — 케이스 내 호스트 간 공유.
- **호스트 분석** (선택 호스트)
  - **대시보드** — 아티팩트 요약 카드에서 상세 뷰로 점프.
  - **통합 타임라인** — 모든 아티팩트의 시간 이벤트를 하나의 타임라인으로(클릭 시 생성).
- **종합 분석** — 위 가공 테이블을 목적별 화면으로: 시스템/계정(RID 하이재킹 경고, 계정별 이벤트 로그 활동), 실행 이력, Defender(위협 트리아지·보호 상태 타임라인·원본 이벤트로 이동), 레지스트리 특이사항, 브라우저 활동(캘린더·타임라인), RDP 세션 흐름, RDP 캐시 복원 이미지, PowerShell 흐름.
- **원본 데이터** — 원본 파싱 SQLite를 카테고리 트리로. 가상 스크롤 테이블(대용량도 부드럽게), 컬럼 정렬/크기조절/필터, 전체 검색, 행 상세, 교차 참조 링크(예: 요약 항목 → 원본 이벤트 로그 레코드).
- **전역 기간 필터** — 사고 추정 구간을 지정하면 여러 뷰가 그 구간으로 좁혀짐.

```powershell
cd viewer
npm install
npm run dev      # 개발
npm run build    # 프로덕션 빌드
```

## 알려진 범위 밖 항목

- IE `WebCacheV01.dat`(ESE) 전용 파서 미구현
- JumpList의 DestList(핀 고정/접근 횟수/MRU 순서) 미파싱 — LNK 헤더 시각·타겟까지
- SMB 로그온 기반 호스트 연결(4624 type3 / SMBServer 이벤트)은 코드가 준비돼 있으나 등록은 보류
- RDP 캐시는 타일에 화면 좌표가 없어 완전한 화면 복원은 불가 — 이어붙는 조각만 복원

## 새 아티팩트 파서 추가하기

1. `parsers/<이름>_parser.py`에 정의:
   - `ARTIFACT_NAME`, 탐색 기준(`FILENAMES`/`FILE_SUFFIXES`/`CONTENT_MARKER`), `FIELD_ORDER`(시간 컬럼이 맨 앞)
   - `parse(paths) -> dict[str, dict[str, list[dict]]]`(원본별 → 테이블별 → 행) 또는 `dict[str, list[dict]]`
2. `common/registry.py`의 `ARTIFACTS`에 `ArtifactDefinition` 추가 (`category`로 결과 폴더 공유 가능)
3. 시간 필드는 `format_timestamp()`(또는 Chromium이면 `chrome_timestamp()`)로 변환하고, 그 필드가 왜 해당 타임존인지 근거를 주석으로 남길 것
4. 상관/요약이 필요하면 `common/processing.py` 또는 `common/correlate.py`에 빌더를 만들고 `main.py`의 `overview_builders`에 등록

## 프로젝트 구조

```
main.py                     진입점: 케이스/호스트 → 탐색 → 파싱 → SQLite + _OVERVIEW
common/
  finder.py                 파일 탐색(이름/확장자/내용), 중복 제거
  registry.py               아티팩트 등록 목록
  case_store.py             케이스/호스트 메타데이터 관리
  processing.py             가공: TargetInfo/ExecutionHistory/Defender/RegistryFindings/BrowserActivity/RdpCache
  correlate.py              가공: RemoteDesktopHistory/PowerShellHistory (이벤트 로그 상관)
  sqlite_writer.py          dict 리스트 → SQLite 저장(안전한 타입/스키마 처리)
  utils.py                  공통 시간 포맷/변환 규칙
  chrome_time.py            Chromium epoch 시간 변환
  sqlite_utils.py           SQLite 읽기 전용 연결, 안전한 텍스트 디코딩
  browser_id.py             경로에서 브라우저 이름 추출
  hive_recovery.py          레지스트리 하이브 트랜잭션 로그 반영
  hbin_carver.py            삭제된 레지스트리 셀 카빙
parsers/
  amcache_parser.py  eventlog_parser.py  registry_parser.py  prefetch_parser.py
  jumplist_parser.py  srum_parser.py  usnjrnl_parser.py  wer_parser.py
  taskscheduler_parser.py  rdpcache_parser.py  powershell_history_parser.py
  browser_history_parser.py  browser_cache_parser.py
viewer/                     Electron + Next.js 분석 뷰어 (파이프라인 실행 + 결과 분석)
```
