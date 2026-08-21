# report airodump

`libpcap`으로 Radiotap + IEEE 802.11 패킷을 캡처하여 `airodump-ng`와
비슷한 AP/Station 표를 출력하는 과제 프로젝트입니다.

## 구현 항목

- Beacon Frame: BSSID, PWR, Beacons, #Data, CH, ENC, ESSID
- Data Frame: AP별 데이터 수와 연결된 Station 집계
- Probe Request: 연결되지 않은 Station과 탐색 중인 ESSID 표시
- Radiotap Header: 가변 present bitmap, 필드 정렬, dBm 신호 세기, 주파수 해석
- 보안 방식: OPN, WEP, WPA, WPA2, WPA3 구분
- 선택 기능: `iw`를 이용한 채널 호핑

## 준비

Ubuntu/Debian 기준:

```sh
sudo apt update
sudo apt install build-essential libpcap-dev iw
```

무선 어댑터가 monitor mode를 지원해야 합니다. 아래 명령의 인터페이스 이름은
환경에 맞게 변경합니다.

```sh
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
```

NetworkManager가 채널을 계속 변경하면 해당 인터페이스를 관리 대상에서 제외하거나
`airmon-ng`로 별도의 monitor interface를 만드는 편이 좋습니다.

## 빌드 및 실행

```sh
make
sudo ./airodump mon0
```

채널 호핑을 사용할 때:

```sh
sudo ./airodump mon0 --channels 1,6,11 --hop-ms 500
```

종료는 `Ctrl+C`입니다. 전체 옵션은 `./airodump --help`에서 확인할 수 있습니다.

## 테스트

테스트는 실제 무선 어댑터 없이 만든 Radiotap/802.11 패킷으로 파서와 집계 로직을
확인합니다.

```sh
make test
```

## 시연 영상 체크리스트

1. monitor mode 인터페이스가 보이는 장면
2. `make`가 성공하는 장면
3. `sudo ./airodump mon0 --channels 1,6,11` 실행 장면
4. AP의 BSSID/Beacons/#Data/PWR/ENC/ESSID가 갱신되는 장면
5. Station 및 Probe Request가 나타나는 장면
6. `Ctrl+C`로 정상 종료하는 장면

캡처는 본인 소유 또는 명시적으로 허가받은 네트워크에서만 수행합니다.
