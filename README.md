# ESXi VM -> Windows create
ESXi shell를 열어서 pip-paramiko 모듈을 이용하여 SSH 연결

Windows.iso는 수동을 설치해줘야 한다.
Windows.iso의 경로를 config.py에 지정하여 ESXi의 /vmfs/volumes/datastore1/iso/에 파일을 전송한다.

`vim-cmd` 명령어를 이용하여 VM을 구축한다.