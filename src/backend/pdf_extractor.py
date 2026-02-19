import os
from typing import Optional
from pdfminer.high_level import extract_text

def extract_pdf_text(input_path: str) -> str:
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"File not found: {input_path}")
    return extract_text(input_path) or ""

def save_text(text: str, output_path: str) -> None:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(text)

def extract_to_file(input_path: str, output_dir: Optional[str] = None) -> str:
    base = os.path.splitext(os.path.basename(input_path))[0]
    output_dir = output_dir or os.path.join(os.path.dirname(input_path), "extracted")
    output_path = os.path.join(output_dir, f"{base}.txt")
    text = extract_pdf_text(input_path)
    save_text(text, output_path)
    return output_path

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python -m src.backend.pdf_extractor <pdf_path> [output_dir]")
        sys.exit(1)
    pdf_path = sys.argv[1]
    out_dir = sys.argv[2] if len(sys.argv) > 2 else None
    out_file = extract_to_file(pdf_path, out_dir)
    print(out_file)
