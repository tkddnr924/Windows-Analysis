# Windows-Analysis

수집된 Windows 아티팩트(레지스트리 하이브, 이벤트 로그, 브라우저 DB/캐시, 점프리스트, 프리패치, SRUM, RDP 캐시, `$MFT`/`$UsnJrnl` 등)를 침해사고 분석에 쓰기 좋게 처리하는 DFIR 트리아지 툴입니다.

두 단계로 동작합니다.

1. **원본 파싱** — 각 아티팩트를 원본에 1:1로 대응하는 SQLite로 충실히 변환합니다. 값을 함부로 추측·가공하지 않고, 깨진 부분도 흔적을 남깁니다. 삭제된 레지스트리 셀·트랜잭션 로그 항목까지 복구해(`_recovery` 표시) 최대한 파싱합니다.
2. **가공(종합 분석)** — 여러 아티팩트를 교차 상관해 분석가가 실제로 보고 싶은 요약 테이블(`_OVERVIEW/`)을 만듭니다. 시스템/계정 개요(TargetInfo), 실행 이력 통합(ExecutionHistory), Defender 활동, 레지스트리 특이사항, RDP/SMB/PowerShell 이력, 브라우저 활동 등.

전체 스택은 **Rust**입니다.

- **파싱 코어 + CLI** (`rust/`) — `wina-core` 라이브러리와 `wina` CLI. 모든 파서·상관 빌더가 순수 Rust로 구현되어 빠르고, 단일 정적 바이너리로 배포됩니다.
- **데스크톱 뷰어** (`viewer/`) — **Tauri + Next.js/React**. 파싱부터 분석까지 앱 안에서 케이스 단위로 진행합니다. CLI형 작업은 `wina` 바이너리를 sidecar로 호출하고, 결과 열람은 앱 내부에서 SQLite를 직접 읽습니다.

GitHub Actions가 macOS·Windows용 `wina` CLI와 Tauri 앱을 빌드합니다.

> 이 저장소의 코드에는 특정 사건/조직/호스트에 종속된 값(IP·호스트명·계정명 등)을 하드코딩하지 않습니다. 모든 파서·상관 규칙은 Windows/포렌식 도메인의 일반 지식만 사용합니다.

## 요구 사항

- Rust (stable, 2021 edition) — 파싱 코어/CLI/Tauri 백엔드
- Node.js 20+ — 뷰어 프런트엔드
- 개발/테스트는 macOS·Windows 모두 가능 (SRUM용 `libesedb`는 C 소스에서 함께 빌드됩니다)

## 빌드 & 실행

### CLI (`wina`)

```bash
cd rust
cargo build --release -p wina
# 사용 예
./target/release/wina --list-artifacts
./target/release/wina --create-case <이름> --cases-dir <경로>
./target/release/wina --run-host <caseId> --host <hostId> --cases-dir <경로> [--only Amcache,EventLog]
```

`wina`는 케이스 디렉터리(`cases/<caseId>/<hostId>/`) 아래에 아티팩트별 SQLite와 `_OVERVIEW/` 요약 테이블을 씁니다.

### 데스크톱 뷰어 (Tauri)

```bash
cd viewer
npm install
npm run dev        # tauri dev — 개발용 창 (Next dev 서버 + 네이티브 WebView)
npm run build      # tauri build — 배포용 앱 번들 (.app/.dmg, .msi/.exe)
```

개발 모드에서 `wina` 바이너리 위치와 케이스 폴더는 환경변수로 덮어쓸 수 있습니다.

```bash
WINA_BIN=../rust/target/release/wina WINA_CASES_DIR=../cases npm run dev
```

배포 빌드에서는 `wina`가 앱 번들에 sidecar로 포함되고, 케이스 폴더는 실행 파일 옆의 `cases/`를 사용합니다.

## 저장소 구조

```
rust/
  core/     wina-core — 파서 + 상관(_OVERVIEW) 빌더 + 케이스 저장소
  cli/      wina — CLI 프런트엔드
  VALIDATION.md   Python 원본 대비 검증 로그(파서/빌더별 diff 결과)
viewer/
  app/ components/ lib/   Next.js/React 프런트엔드
  src-tauri/              Tauri 백엔드 (Rust): window.api 커맨드
.github/workflows/build.yml   macOS·Windows 빌드 CI
```

## 검증

각 파서·상관 빌더는 기존 Python 파이프라인 출력과 대조해 검증했습니다(대부분 바이트 단위 0-diff, 나머지는 크레이트 수준 차이/개선 사항을 문서화). 자세한 내용은 [`rust/VALIDATION.md`](rust/VALIDATION.md)를 참고하세요.
