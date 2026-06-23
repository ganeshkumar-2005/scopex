import fitz  # PyMuPDF
import os

def generate_preview():
    pdf_path = os.path.abspath("examples/sample_report.pdf")
    output_image_path = os.path.abspath("assets/report_preview.png")
    
    if not os.path.exists(pdf_path):
        print(f"Error: PDF not found at {pdf_path}")
        return
        
    print(f"Opening PDF at {pdf_path}...")
    doc = fitz.open(pdf_path)
    page = doc.load_page(0)  # Load the first page
    
    print("Rendering page to image...")
    pix = page.get_pixmap(dpi=150)  # 150 DPI matches screen layouts perfectly
    
    os.makedirs(os.path.dirname(output_image_path), exist_ok=True)
    pix.save(output_image_path)
    print(f"Success! PDF page converted and saved to {output_image_path}")

if __name__ == "__main__":
    generate_preview()
