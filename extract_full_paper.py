from pypdf import PdfReader

reader = PdfReader('paper_nit_final (8).pdf')
with open('paper_text.txt', 'w', encoding='utf-8') as f:
    for i, page in enumerate(reader.pages):
        f.write(f'--- page {i+1} ---\n')
        text = page.extract_text()
        f.write(text if text else '')
        f.write('\n\n')
print('wrote paper_text.txt')
