from dynamic_analysis.MA_DA import *
from static_analysis.MA_SA import *
from CONFIG.config import FINAL_RESULT_OUTPUT_PATH
import json

def process():
    MA_SA_result = process_MA_SA()
    MA_DA_result = process_MA_DA()

    final_result = {
        "StaticAnalysis":MA_SA_result,
        "DynamicAnalysis":MA_DA_result
    }

    with open(FINAL_RESULT_OUTPUT_PATH,"w",encoding='utf-8') as f:
        json.dump(final_result,f,indent=4)

    return json.dumps(final_result,indent=4)

def main():
    print(process())

if __name__=="__main__":
    main()
