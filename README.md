# Check Foundry

Go 기반 로컬 의존성 검사 CLI. M1은 지정한 폴더 바로 아래의 npm package-lock.json 또는 지정한 해당 파일 하나를 OSV-Scanner로 검사한다. 저장소를 순회하거나 패키지를 설치하지 않는다.

## 실행

Go 1.22 이상과 OSV-Scanner v2.7.1이 필요하다. 공식 릴리스 바이너리를 설치한 뒤 실행한다. macOS는 sandbox-exec, Linux는 네트워크 네임스페이스를 생성할 수 있는 bubblewrap 환경이 필요하다. 격리 생성에 실패하면 검사를 중단한다. 실제 통합 검증 플랫폼은 Intel macOS다.

```sh
go build -o ./check-foundry .
# 별도 온라인 준비 작업. Python 3.11+, curl. 입력은 캐시 위치뿐이다.
python3 scripts/prepare-db.py "$HOME/.cache/check-foundry"
export OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="$HOME/.cache/check-foundry"
./check-foundry scan /path/to/project
./check-foundry scan -json /path/to/project/package-lock.json
```

현재 개발 체크아웃에서는 아래 명령에 M0 DB와 프로젝트 전용 바이너리를 사용할 수 있다.

```sh
.cache/tools/check-foundry scan -osv .cache/tools/osv-scanner -db-cache .cache/m0/osv-scanner evaluation/m0/dependency-controls/affected
```

## 결과를 읽는 법

| 종료 코드 | 상태 | 의미 |
|---|---|---|
| 0 | complete | 모든 대상 이름·버전을 고정된 DB로 대조했고 일치 공지 없음 |
| 1 | complete | 일치한 패키지·버전·공지 조합이 하나 이상 있음 |
| 2 | partial / unsupported / failed | 일부 항목 제외·누락, 지원 파일/패키지 없음 또는 입력·DB·도구·격리 실패. 발견 개수와 별도로 처리 |

-json은 stdout에 단일 JSON을 출력한다. findings의 id는 공지 식별자이며 잠긴 버전과의 일치를 의미한다. 실제 배포 또는 취약 코드 실행 여부는 확인하지 않는다. 입력은 v2/v3의 packages 목록을 사용한다. npm 이름과 고정 버전을 읽고 중복된 이름·버전은 한 번 센다. 별도 레지스트리 URL, git·로컬·링크 및 해석할 수 없는 항목은 제외한다. resolved가 없으면 이름·버전을 npm 좌표로 간주하므로 사내 동명 패키지는 결과 해석에 주의한다. 파일 크기 한도 32MiB, 스캐너 결과 64MiB다.

config/offline.json은 실행 버전과 공개 npm DB 스냅샷을 고정한다. prepare-db.py는 파일의 SHA-256을 대조한 뒤 원자적으로 캐시를 교체한다. 이 명령을 다시 실행해도 최신 시점으로 이동하지 않는다. 현재 정책은 재현 가능한 **고정 시점 검사**다. 스캔 때마다 DB 해시와 OSV 버전을 확인하고, 메타데이터를 줄인 임시 lockfile만 OSV에 전달한다. OSV는 네트워크와 일반 파일 쓰기가 제한된 별도 프로세스에서 실행한다. 원본 scanner stdout/stderr는 저장하지 않는다.

## 검증

```sh
go test ./...
python3 evaluation/m1/acceptance.py ./check-foundry /path/to/osv-scanner "$OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"
```

[마일스톤](milestones.md) · [아키텍처](security-scope.md) · [M0 기준](evaluation/m0/README.md)
