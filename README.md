# Malware Analysis Automation

- vmware workstation pro 설치
    - https://support.broadcom.com/group/ecx에서 로그인 후, 설치
    - My Downloads
    - 페이지2에서 VMware Workstation Pro
    - VMware Workstation Pro 17.0 for Windows 다운로드

- 바탕 화면에 working폴더를 생성(파일명: sandbox)
- working폴더 안에 ISO 설치, 있으면 넘어감(VMware-VMvisor-Installer-8.0U3b-24280767.iso)
- working폴더 안에 vmware문서폴더 생성(파일명: vmware)
- vmware문서폴더 안에 OS이미지구성파일폴더 생성(파일명: ESXi_sandbox)
- OS이미지구성파일폴더 안에 vmx, vmdk 생성
  - vmx 생성(config)
  - vmware-vdiskmanager을 이용하여 vmdk 생성(config)
  - s00x.vmdk 생성(저장파일)
  - nvram, scoreboard, vmsd, vmxf, vmem, log는 실행하면 자동 생성
