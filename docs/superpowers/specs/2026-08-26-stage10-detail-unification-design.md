# Stage 10 공통 상세보기 통합 설계

## 목표

모든 증거 레코드 진입점이 하나의 `openRecordDetail(DetailTarget)` 경로를 사용하고, 동일한 `RowDetailPanel`에서 동일한 제목·필드·시간·provenance·북마크 상태를 표시한다. Legacy, Normalized, Candidate V14의 identity와 snapshot pin은 서로 혼합하거나 추론하지 않는다.

AI 대화, 도메인 통계, 코드·캐시 본문 확대처럼 레코드 상세가 아닌 bounded workflow는 독립 표면으로 유지한다. 새 상세 Drawer·Dialog는 만들지 않는다.

## 접근 방식

단계적 전환을 사용한다. 한 번에 모든 화면을 교체하면 MFT docked inspector, 파생 provenance, Browser Cache preview, Legacy bookmark 의미가 동시에 흔들린다. 화면별 adapter만 추가하는 방식은 현재의 분산된 취소·북마크·identity 조립을 남긴다. 따라서 공통 계약과 controller를 먼저 고정한 뒤 진입점을 순차 전환한다.

## 타입과 identity

`DetailTarget`은 backend별 discriminated union이다.

```ts
type DetailTarget =
  | {
      backend: "legacy";
      hostId: string;
      artifact: string;
      source: { fullPath: string; tableName: string; rowid: number };
      focus?: DetailFocus;
    }
  | {
      backend: "normalized";
      hostId: string;
      artifact: string;
      dataset: LogicalDataset;
      recordKey: string;
      generationId: string;
      snapshotDigest: string;
      focus?: DetailFocus;
    }
  | {
      backend: "candidateV14";
      hostId: string;
      artifact: string;
      recordKey: string;
      generationId: string;
      factsSha256: string;
      derivedSha256: string;
      focus?: DetailFocus;
    };

type DetailFocus =
  | { kind: "record" }
  | { kind: "time"; observationKey: string; fieldKey: string }
  | { kind: "field"; fieldKey: string };
```

Legacy의 path/table/rowid는 Legacy adapter 안에서만 허용한다. Normalized와 Candidate target에는 이를 넣지 않는다. `recordKey`, `observationKey`, `fieldKey`, 표시 라벨은 서로 대체하지 않는다.

## 공통 controller

앱 단위 `DetailController`가 다음을 소유한다.

- `openRecordDetail(target)`와 현재 target
- backend별 bounded loader 선택
- exact generation/snapshot/hash pin 유지
- detail과 provenance의 병합
- request ID 생성, cancel lease, sequence 기반 stale 응답 차단
- target 변경, drawer 닫기, host/view 변경, unmount 시 취소
- record/time/field `BookmarkSubject` 변환과 revision-aware mutation
- 명시적 Browser Cache/RDP preview action과 닫기·전환 시 preview 취소

`RowDetailPanel`은 네트워크·DB 조회나 identity 추론을 하지 않고 완성된 view model과 명시적 action만 렌더링한다.

## 상세 응답과 presentation

공통 view model은 다음 정보를 포함한다.

- authoritative target와 canonical artifact view ID
- 제목, summary/full/source fields
- 모든 time observations와 parse status/raw value
- provenance 및 bounded related evidence
- record/time/field bookmark states와 revision
- preview capability와 명시적 action
- loading, not-found, transient error 상태

필드 라벨과 구조는 `artifactViews`가 단일 소유한다. 화면은 필드 배열이나 한글 라벨을 새로 만들지 않는다. focus 대상은 패널 open 시 한 번 scroll/focus하고 낮은 채도의 선택 강조를 사용한다. 현재 상세에 없는 focus는 상세를 유지하면서 `선택한 필드를 현재 상세에서 찾을 수 없습니다` 상태로 표시한다.

## backend adapter

### Legacy

기존 result-row, provenance, linked-row, bookmarks JSON 의미를 유지한다. host 소속과 안전한 source path를 검증한다. Legacy target을 normalized identity로 합성하지 않는다.

### Normalized

기존 exact generation pin의 `normalized_record_detail`, provenance, bounded preview 경로를 재사용한다. current swap이 발생해도 열린 drawer는 최초 pin을 유지한다. derived record의 모든 fact link 역할과 ordinal을 반환한다.

### Candidate V14

facts/derived SHA pin을 유지하고 record detail, time observation, related context, AnalystStore v2 bookmark를 결합한다. timeline bookmark identity는 정확한 `observationKey`이며 record bookmark와 독립이다.

## 진입점 전환 순서

1. 10A: 공통 타입, validator, target-to-bookmark 변환. production 연결 없음.
2. 10B: backend별 detail adapter와 공통 bounded envelope, exact pin·취소 테스트.
3. 10C: 앱 단위 controller/hook와 공통 view model.
4. 10D: 원본 테이블과 MFT/Browser/EventLog 전환.
5. 10E: 파생 뷰와 related evidence 전환.
6. 10F: 통합 타임라인, 검색, 북마크 뷰 전환.
7. 10G: 패널 내부 record-key 정규식과 화면별 snapshot 조립·사용되지 않는 상세 모달 제거.
8. 10H: 정적 강제 장치, 전체 자동화·성능·native UI 게이트.

전환 중 한 화면에서 old/new 상세 경로를 동시에 사용하지 않는다. Legacy와 Normalized 데이터나 북마크 mutation도 한 target에서 혼합하지 않는다.

## 오류 처리

- 존재하지 않는 target은 snapshot으로 대체하지 않고 `not_found`로 표시한다.
- 손상 pin, digest mismatch, stale generation은 Legacy/current로 fallback하지 않는다.
- provenance 일부 실패는 성공한 detail을 유지하고 식별 가능한 부분 오류를 표시한다.
- close나 빠른 행 전환 뒤 도착한 응답은 commit하지 않는다.
- preview 실패는 패널의 visible alert로 표시하며 metadata detail은 유지한다.

## 테스트

### 자동화

- 세 target variant의 strict serialization과 cross-field 거부
- 동일 숫자·문자 identity의 backend/host 간 충돌 방지
- g1 목록 후 current g2 전환 시 g1 detail/provenance 유지
- Candidate record/time/field bookmark 독립 왕복, revision conflict, 재생성 보존
- BrowserActivity derived key와 fact provenance/cache preview 연결
- cancel-before/during/after, 빠른 target 변경, out-of-order 응답
- 원본·파생·타임라인·검색·북마크에서 동일 view model/provenance/bookmark 상태
- normalized/candidate target에 path/table/rowid가 없고 자동 preview가 없는 정적 계약
- renderer의 독자 Drawer·Dialog·snapshot 상세 경로 금지

### native UI

Legacy와 Normalized/Candidate fixture에서 원본, 파생, 타임라인, 검색, 북마크 진입을 각각 조작한다. 동일 패널의 제목·핵심/전체/시간/원본 필드, focus, 북마크 동기화, related navigation, preview, close/Escape, rapid row switch를 확인한다. 큰 창과 760x620에서 상·중·하단 스크롤, drawer layering, focus return, 잘림·겹침, 콘솔/Tauri 오류를 검증한다.

## 호환성과 제외 범위

- 기존 Legacy case를 migration/backfill/delete하지 않는다.
- Stage 8 parity가 blocked인 13개 artifact 때문에 production 기본 writer 전환이나 Legacy reader 제거를 Stage 10 완료로 주장하지 않는다.
- Candidate V14와 AnalystStore v2는 명시적 candidate route에서만 사용한다.
- 성능은 동일 fixture의 첫 상세, linked navigation, bookmark, preview p50/p95와 IPC byte cap을 기록하며 정확성 조건이 다른 결과를 비교하지 않는다.

## 완료 기준

10A~10H가 순서대로 통과하고, Agent 3이 자동화와 실제 앱의 모든 대표 진입점을 독립 검증해 `OK`를 명시해야 완료다.
