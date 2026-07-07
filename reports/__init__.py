# ScopeX Reports Package
from .pdf_report import generate_pdf_report
from .sarif_report import generate_sarif_report

__all__ = ['generate_pdf_report', 'generate_sarif_report']
