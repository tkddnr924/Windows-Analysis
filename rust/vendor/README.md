# vendor/

크레이트를 저장소에 두고 `[patch.crates-io]`로 대체하는 곳. 빌드에 반드시
필요하므로 `.gitignore` 대상이 아니다(무시하면 GitHub Actions 릴리스 빌드가
경로 의존성을 찾지 못해 실패한다).

## libesedb-sys

crates.io `libesedb-sys` 0.2.1 + 다운스트림 패치. SRUM(SRUDB.dat)·IE WebCache
(WebCacheV01.dat) 파싱이 이 라이브러리를 쓴다.

추가한 패치는 `patches/fix-win11_page_tag_flags.patch` 하나다. Windows 11의 ESE는
페이지 헤더 available page tag 필드 상위 비트에 플래그를 넣는데(태그 수는 하위
12비트), libesedb-20230824는 이를 모르고 태그 수 범위 검사에서 파일 자체를
거부한다 — 손상되지 않은 Win11 SRUDB.dat이 "손상"으로 건너뛰어지던 원인.
패치는 크레이트 자신의 `build.rs` 패치 적용 기구를 그대로 쓴다.

### 트리에서 제거한 것

`build.rs`는 `lib*/*.c`만 컴파일하고 `include/`·`common/`만 include 경로로 쓴다.
따라서 빌드에 쓰이지 않는 autotools(configure·m4·ltmain.sh·Makefile.*),
tests·msvscpp·pyesedb·esedbtools·po·manuals 등은 벤더링 시 제거했다
(1,034 → 666 파일, 16MB → 9.3MB). 라이선스 파일(LGPL)은 남겨둔다.

업스트림을 새 버전으로 올릴 때는 crates.io 원본을 다시 복사한 뒤 같은 기준으로
정리하고, `patches/`의 패치가 여전히 적용되는지 확인할 것.
