from pypdf import PdfReader
import os

path = 'paper_nit_final (8).pdf'
print('exists', os.path.exists(path))
reader = PdfReader(path)
print('pages', len(reader.pages))
for i, page in enumerate(reader.pages[:3]):
    text = page.extract_text()
    print(f'--- page {i+1} ---')
    print(text[:2000])
