# Malware Analysis Automation 
- Static Analysis Automation 
## Usage Guide
- Add the file to the Malware_sample folder
```
cd static_analysis (Path movement)
python main.py (Run)
```

## static analysis checklist
### upx install
- window & mac os
    - [upx download](https://github.com/upx/upx/releases/tag/v4.2.4)

- kali Linux  
    ```
    sudo apt update
    sudo apt install upx -y
    upx --version 
    ```

### virustotal API
1. To use the API, join the [virustotal community](https://www.virustotal.com/gui/home/upload)
2. After creating the config.ini file [DEFAULT] VT_API_KEY = Put your key in 


## yara rule refrence
- [naxonez](https://github.com/naxonez/YaraRules)
- [reversinglabs](https://github.com/reversinglabs/reversinglabs-yara-rules)
- [MalGamy](https://github.com/MalGamy/YARA_Rules)
- [embee-research](https://github.com/embee-research/Yara-detection-rules/tree/main)
- Will be continuously modified and added...


## Dynamic Analysis 
### setup sandbox (layer 1)

```
python main.py -E
```

### setup sandbox Windows 10 (layer 2)

```
python main.py -W
```
