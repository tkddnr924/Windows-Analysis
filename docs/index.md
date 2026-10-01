# Windows-Analysis 위키

프로젝트 목적, 기능, 데이터 처리, 디자인과 사용자 확정 결정을 관리하는 Markdown 위키다.
이 문서들은 기존 AGENTS.md에서 이관한 필수 프로젝트 규칙이며, 위치 변경으로 효력이 달라지지 않는다.
공통 작업 절차는 [AGENTS.md](../AGENTS.md)를 따른다. 작업 시작 시 이 목차와 해당 주제 문서를 확인한다.

## 프로젝트

- [프로그램 목적](products/windows-analysis.md)

## 프로젝트 규칙

- [앱 구조와 데이터 관리](patterns/application.md)
- [디자인 규칙](patterns/design.md)
- [파싱 아키텍처와 데이터 보존](patterns/parsing.md) — Chromium History WAL 처리·검증 포함
- [DFIR 분석 뷰](patterns/dfir-analysis.md) — 북마크 사건 시각과 원본 키 시각 구분
- [호스트 연결 3D 뷰](patterns/host-connections.md)

## 관리

- 기능 구현 완료 후 위키에 남길 요구 사항·동작·결정·제약·검증 근거를 해당 문서에 반영한다.
- 기존 페이지를 먼저 갱신하고, 독립적으로 참조할 새 주제는 별도 Markdown 페이지로 만든다.
- 기존 확정 사항과 예외를 보존하고, 변경된 결정에는 날짜와 근거를 남긴다. 미구현 계획을 구현된 기능으로 기록하지 않는다.
- 문서를 추가·변경할 때 목차와 관련 문서 링크를 갱신하고 [변경 이력](log.md)에 기록한다.
- `[[patterns/design]]` 같은 위키 링크는 docs를 기준으로 해석한다. 목차는 일반 Markdown 링크로 탐색할 수 있다.
