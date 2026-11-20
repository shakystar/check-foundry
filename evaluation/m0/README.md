# M0 — 재현 가능한 평가 입력
제품 CLI는 Go로 개발한다. 이 디렉터리의 Python 3 스크립트는 Git 객체를 읽는 평가 준비 도구다. Juice Shop을 설치하거나 실행하지 않는다.

## 입력 준비
[앱 v20.3.0](https://github.com/juice-shop/juice-shop/tree/f189f521266f42c6bd05884468292000cee852ed)과 [공식 가이드](https://github.com/juice-shop/pwning-juice-shop/tree/525df2a65d48abf736efd4873ba2b4d276d172a8)를 사용한다. 가이드의 버전 속성과 앱 package.json이 일치해야 한다. Git이 해당 커밋을 보유하면 작업 트리가 바뀌어도 실행 결과는 같다.

```sh
git clone --branch v20.3.0 --depth 1 https://github.com/juice-shop/juice-shop.git /tmp/cf-app
git clone https://github.com/juice-shop/pwning-juice-shop.git /tmp/cf-guide
python3 evaluation/m0/prepare.py /tmp/cf-app /tmp/cf-guide /tmp/cf-input
```

출력 폴더는 새 경로여야 한다. 준비기는 공식 주석을 떼되 빈 줄을 보존하고, 원본 위치와 입력 SHA-256을 expected-mapping.json과 비교한다. 원본 행 = 매핑 시작 행 + 입력 행 − 1. 스캐너에는 scan/ 안의 해당 split 파일만 전달한다. mapping.json, 기준표, 원본 저장소, 가이드, 정답 파일명은 전달하지 않는다. M2 규칙 개발에는 development 쌍만 사용하고 규칙 해시를 고정한 뒤 holdout 쌍을 평가한다. 공개 기준이라 비밀 시험 세트는 아니다.

## 분모와 판정
- 개발 사례 한 쌍과 보류 사례 한 쌍. 각 쌍은 원본 코드 조각 1개와 공식 수정본의 대응 조각 1개다. baseline.json의 locations는 upstream 행 번호다. 안전 판정은 해당 결함에만 적용한다. 예를 들어 개발 사례의 공개 표준 메타데이터 경로는 비공개 파일 경로와 구별한다.
- 탐지 적중은 동일 결함·동일 파일에서 기대 행 중 하나 이상과 겹쳐야 한다. 함께 매핑된 기대 행 수를 따로 기록한다. 권고 적합성은 공식 수정 의도를 충족하면 1, 무관하거나 해당 통제를 구현하지 못하면 0, 근거 부족은 보류로 남긴다. 동등한 다른 수정은 검토할 수 있다.
- split별로 양성 1건에 대한 적중/누락, 대조 1건에 대한 해당 결함 오경고, 권고 적합/부적합/보류를 **개수로** 보고한다. 수행하지 못한 검사는 미측정이다. 출력이 없는 실패를 음성으로 세지 않는다. 공식 목록 밖 발견은 미분류다.
- 입력은 작은 정적 조각이다. 미들웨어 전체 흐름, 실제 공개 여부, 취약점 재현, 프로젝트 전체 탐지율은 측정하지 않는다. 원본 앱은 MIT, 가이드는 CC BY-NC-ND 4.0이다. 가이드 본문과 공식 해답 코드를 이 저장소에 복제하지 않는다.

## 적용 범위 장부
| 위험군 | M0 취급 |
|---|---|
| 파일·경로·업로드 | 개발용: 의도치 않은 파일 목록/일반 제공 설정에 한정 |
| 배포·인프라 경계 | 보류 평가용: 운영 지표 핸들러 접근 통제 후보에 한정. 실제 배포 상태 미확인 |
| 종속성·빌드 공급망 | 합성 npm v3 lockfile 2개로 특정 GHSA 일치 여부만 검증. 실제 앱 의존성 및 CI 무결성 미확인 |
| 인증·계정 복구 / 세션·토큰·연합 인증 / 인가·테넌트 격리 | 미측정. 지표 사례로 일반 사용자 권한 검증을 대신하지 않는다 |
| 입력·쿼리·실행 / 브라우저·교차 출처 / 서버 측 통신 | 미측정 |
| 비밀·암호·전송 / 민감 데이터·관측 / 업무 무결성·남용 | 미측정 |

## M1 인계
고정된 앱에는 실제 npm lockfile이 없다. 교육용 백업 파일과 합성 대조군을 앱의 설치 트리로 취급하지 않는다. dependency-controls의 두 파일은 [GHSA-35jh-r3h4-6jhm](https://github.com/advisories/GHSA-35jh-r3h4-6jhm) 하나에 대해 lodash 4.17.20은 일치, 4.17.21은 불일치를 기대한다. 수정 버전에서 다른 공지가 나오는 것은 이 대조의 실패가 아니다.

baseline.json은 OSV-Scanner 및 Semgrep CE의 목표 릴리스를 고정한다. OSV-Scanner는 Apache-2.0, Semgrep CE 엔진은 LGPL-2.1이며 엔진 라이선스와 개별 규칙 사용 조건은 별도다. M0에 배포하는 탐지 규칙은 0개다. M2에서 실제 규칙마다 원본·라이선스·해시를 추가해야 한다. M0 검증은 입력 준비와 기준 검증이며 스캐너 설치·오프라인 실행·정확도 측정은 이후 단계다.

DB의 generation URL과 실제 SHA-256은 baseline.json에 있다. 내려받은 zip은 로컬 캐시에 보존한다. 재현 검증 명령(Python 3.11 이상):

```sh
python3 evaluation/m0/verify_db.py .cache/m0/osv-scanner/osv-scalibr/npm/all.zip
```
