"""Генерация отчётов: HTML и PDF."""

from .html_report import render_document
from .pdf_report import render_pdf_bytes, render_pdf_file
from .trend_report import TrendPoint, render_trend_html

__all__ = ["render_document", "render_pdf_bytes", "render_pdf_file",
           "TrendPoint", "render_trend_html"]
