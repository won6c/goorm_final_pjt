import os
import numpy as np
from datasets import Dataset
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer
)

# ------------------------
# 하이퍼파라미터 설정
# ------------------------
MODEL_NAME = "roberta-base"  # Hugging Face Model Hub에서 인증 없이 다운로드 가능
MAX_LENGTH = 128             # 한 텍스트(Imports 리스트 등)에 대해 토큰 길이 제한
NUM_LABELS = 2               # 이진 분류 (0=정상, 1=악성 등)
BATCH_SIZE = 16              # GPU 메모리에 맞춰 조정
EPOCHS = 5
LR = 2e-5
OUTPUT_DIR = "./roberta_malware_model"

def main():
    # ------------------------
    # 1) 임의 데이터 준비 (악성=1, 정상=0)
    # 실제 프로젝트에선 바이너리 DLL/EXE에서 Imports 추출한 문자열 사용
    # 여기서는 예시로 단순 문자열과 라벨로 Dataset 구성
    texts = [
        "kernel32.dll VirtualAlloc ...",  # 악성 예시?
        "user32.dll normal usage ...",    # 정상 예시?
        "ntdll suspicious hooking ...",
        "comdlg32 benign calls ...",
    ]
    labels = [1, 0, 1, 0]  # 예시

    # Hugging Face Dataset 생성
    raw_dataset = Dataset.from_dict({"text": texts, "label": labels})

    # train_test_split(예시로 80:20 나누기)
    splitted = raw_dataset.train_test_split(test_size=0.2)
    train_dataset = splitted["train"]
    val_dataset   = splitted["test"]

    # ------------------------
    # 2) 토크나이저/모델 불러오기
    # ------------------------
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_NAME, 
        num_labels=NUM_LABELS
    )

    # ------------------------
    # 3) 토큰화 함수 정의
    # ------------------------
    def tokenize_function(examples):
        return tokenizer(
            examples["text"],
            max_length=MAX_LENGTH,
            truncation=True,
            padding="max_length"
        )

    # 토큰화 적용
    train_dataset = train_dataset.map(tokenize_function, batched=True)
    val_dataset   = val_dataset.map(tokenize_function,   batched=True)

    # trainer가 사용하지 않는 컬럼(원본 'text') 제거
    remove_cols = list(set(train_dataset.column_names) - {"input_ids", "attention_mask", "label"})
    train_dataset = train_dataset.remove_columns(remove_cols)
    val_dataset   = val_dataset.remove_columns(remove_cols)

    # 최종 포맷 설정
    train_dataset.set_format("torch")
    val_dataset.set_format("torch")

    # ------------------------
    # 4) TrainingArguments / Trainer 설정
    # ------------------------
    training_args = TrainingArguments(
        output_dir=OUTPUT_DIR,
        num_train_epochs=EPOCHS,
        per_device_train_batch_size=BATCH_SIZE,
        per_device_eval_batch_size=BATCH_SIZE,
        evaluation_strategy="epoch",
        save_strategy="epoch",
        learning_rate=LR,
        logging_steps=10,
        load_best_model_at_end=True
    )

    def compute_metrics(eval_pred):
        # 단순 Accuracy 계산
        logits, labels = eval_pred
        preds = np.argmax(logits, axis=-1)
        accuracy = (preds == labels).mean()
        return {"accuracy": accuracy}

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        tokenizer=tokenizer,
        compute_metrics=compute_metrics
    )

    # ------------------------
    # 5) 모델 학습
    # ------------------------
    print("Starting training...")
    trainer.train()

    # ------------------------
    # 6) 모델 저장
    # ------------------------
    trainer.save_model(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)
    print("Model saved to:", OUTPUT_DIR)

if __name__ == "__main__":
    main()
