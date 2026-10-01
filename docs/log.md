# 위키 변경 이력

## 2026-09-10: AGENTS.md 프로젝트 규칙 이관

- 출처: 이관 전 AGENTS.md와 사용자의 지침·위키 분리 요청.
- 추가: [프로그램 목적](products/windows-analysis.md), [앱 구조와 데이터 관리](patterns/application.md), [디자인 규칙](patterns/design.md), [파싱 규칙](patterns/parsing.md), [DFIR 분석 뷰](patterns/dfir-analysis.md), [호스트 연결 3D 뷰](patterns/host-connections.md).
- 추가: [목차](index.md) 및 각 주제의 관련 문서 상호 참조.
- 변경: AGENTS.md는 공통 작업 지침과 계획·검증·위키 관리·주석 규칙을 관리한다.
- 기존 프로젝트 규칙·확정 예외는 원문 보존. 이관은 새로운 기능 구현 또는 구현 상태 검증을 의미하지 않는다.

## 2026-09-10: WebView2 사용자 데이터 폴더 검증 근거 기록

- 출처: 앱 산출물을 `cases/` 안에만 두라는 사용자 확정과 구현 결과.
- 변경: [앱 구조와 데이터 관리](patterns/application.md)의 `cases/.webview` 규칙에 회귀 테스트
  (`case_store::tests::app_internal_directories_at_cases_root_are_not_hosts`)와 Windows 전용 미검증 범위를 명시.
- 구현 위치: `viewer/src-tauri/src/main.rs`의 `webview_data_dir()`·`.setup()`, `viewer/src-tauri/tauri.conf.json`의 `"create": false`.

## 2026-09-22: Chromium History WAL 누락 수정

- [파싱 규칙](patterns/parsing.md)에 History의 WAL 처리와 원본 보존·검증 근거를 기록하고
  [목차](index.md)를 갱신했다.
- 기존 immutable 열기의 WAL 테이블·행 누락을 실패 선행 테스트로 재현했다.
  산출물 폴더 내 DB/보조 파일 복사본을 일반 read-only 모드로 읽도록 수정했다.
- History 관련 6개 테스트, core/CLI·Tauri cargo check, CLI 빌드와 실제 호스트 파싱을 통과했다.
  개발 앱 실행 및 HTTP 200 응답을 확인했다. Windows exe 실행과 사용자 실패의 동일 원인 여부는 미검증이다.

## 2026-09-22: 북마크 상세 시각 불일치 수정

- [DFIR 분석 뷰](patterns/dfir-analysis.md)에 북마크 목록·상세의 시각 일치와 원본 시각 보존 규칙을 기록했다.
- `BookmarksView`가 사건 시각을 공통 상세 패널에 전달하지 않아 Registry `last_write`로
  대체되던 경로를 수정했다. 원본 데이터와 저장된 북마크는 변경하지 않는다.
- 실패 선행 React 렌더링 스모크, 수정 후 통과, 타입 검사·16개 테스트·개발 앱 HTTP 200으로 검증했다.
  사용자 실 데이터의 동일 원인 여부와 Windows 실행은 미검증이다.
