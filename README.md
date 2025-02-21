# Local Host -> ESXi VM

- vmware workstation pro 설치
  - https://support.broadcom.com/group/ecx에서 로그인 후, 설치
  - My Downloads
  - 페이지2에서 VMware Workstation Pro
  - VMware Workstation Pro 17.0 for Windows 다운로드

- Windows.iso 설치
  - https://www.microsoft.com/ko-kr/software-download/windows10에서 MediaCreationTool_22H2.exe 설치
  - MediaCreationTool_22H2.exe을 통해 Windows.iso 생성

- configuration/basic_config.py에서 환경설정 수정정

- 바탕 화면에 working폴더를 생성(파일명: sandbox)
- working폴더 안에 ISO 설치, 있으면 넘어감(VMware-VMvisor-Installer-8.0U3b-24280767.iso)
- working폴더 안에 vmware문서폴더 생성(파일명: vmware)
- vmware문서폴더 안에 OS이미지구성파일폴더 생성(파일명: ESXi_sandbox)
- OS이미지구성파일폴더 안에 vmx, vmdk 생성
  - vmx 생성(config)
  - vmware-vdiskmanager을 이용하여 vmdk 생성(config)
  - s00x.vmdk 생성(저장파일)
  - nvram, scoreboard, vmsd, vmxf, vmem, log는 실행하면 자동 생성

- 수동 동작해야 할 것
  - 사용자 계정 생성일 때 수동으로 동작해주어야 한다.
  - enter -> f11 -> enter -> enter -> 비밀번호 후 enter -> f11 -> enter(reboot)


# ESXi VM -> Windows create
ESXi shell를 열어서 pip-paramiko 모듈을 이용하여 SSH 연결

Windows.iso는 수동을 설치해줘야 한다.
Windows.iso의 경로를 config.py에 지정하여 ESXi의 /vmfs/volumes/datastore1/iso/에 파일을 전송한다.

`vim-cmd` 명령어를 이용하여 VM을 구축한다.