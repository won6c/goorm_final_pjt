import os
import numpy as np
from datasets import load_dataset
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer
)

# 이전에 학습해둔 모델이 저장된 디렉토리 경로
MODEL_PATH = os.path.join(os.getcwd(), "LLM", "roberta_malware_model")

# 새로운 CSV 데이터 (columns: "text","label")
CSV_PATH = os.path.join(os.getcwd(), "LLM", "train_data.csv")

MAX_LENGTH = 128
NUM_LABELS = 2
BATCH_SIZE = 16
EPOCHS = 3
LR = 2e-5
OUTPUT_DIR = os.path.join(os.getcwd(), "LLM", "roberta_malware_model_updated")

def main():
    # 1) CSV 로드
    dataset_dict = load_dataset("csv", data_files={"train": CSV_PATH})
    raw_dataset = dataset_dict["train"]

    # 예: train/val 80:20 분할
    splitted = raw_dataset.train_test_split(test_size=0.2)
    train_dataset = splitted["train"]
    val_dataset   = splitted["test"]

    # 2) 이전 모델(토크나이저) 불러오기
    tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_PATH,
        num_labels=NUM_LABELS
    )

    # 3) 토큰화 함수 (문자열 변환)
    def tokenize_function(examples):
        # examples["text"]가 리스트(배치 모드)일 때, 각 항목을 str 변환
        text_list = examples["text"]
        text_list = [str(t) if t is not None else "" for t in text_list]
        return tokenizer(
            text_list,
            truncation=True,
            max_length=MAX_LENGTH,
            padding="max_length"
        )

    train_dataset = train_dataset.map(tokenize_function, batched=True)
    val_dataset   = val_dataset.map(tokenize_function,   batched=True)

    # trainer가 사용하지 않는 컬럼(예: 'text') 제거
    remove_cols = list(set(train_dataset.column_names) - {"input_ids", "attention_mask", "label"})
    train_dataset = train_dataset.remove_columns(remove_cols)
    val_dataset   = val_dataset.remove_columns(remove_cols)

    train_dataset.set_format("torch")
    val_dataset.set_format("torch")

    # 4) Trainer 설정
    training_args = TrainingArguments(
        output_dir=OUTPUT_DIR,
        num_train_epochs=EPOCHS,
        per_device_train_batch_size=BATCH_SIZE,
        per_device_eval_batch_size=BATCH_SIZE,
        evaluation_strategy="epoch",
        save_strategy="epoch",
        learning_rate=LR,
        logging_steps=20,
        load_best_model_at_end=True
    )

    def compute_metrics(eval_pred):
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

    # 5) 추가 학습(재학습)
    print("Starting re-training with previously saved model...")
    trainer.train()

    # 6) 모델 저장
    trainer.save_model(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)
    print("Re-trained model saved to:", OUTPUT_DIR)

if __name__ == "__main__":
    main()
