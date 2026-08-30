import fitz
import os

path = r"paper_nit_final (8).pdf"
print('exists', os.path.exists(path))
with fitz.open(path) as doc:
    print('pages', doc.page_count)
    for i in range(min(3, doc.page_count)):
        print(f"--- page {i+1} ---")
        print(doc[i].get_text()[:2000])
