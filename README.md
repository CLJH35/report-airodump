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

## 빌드 및 실행

```sh
make
sudo ./airodump mon0
```

