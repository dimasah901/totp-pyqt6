from PyQt6.QtWidgets import QTableWidget
from PyQt6.QtCore import pyqtSignal
from PyQt6.QtGui import QFocusEvent

class FocusTable(QTableWidget):
    focusIn = pyqtSignal(QFocusEvent)
    focusOut = pyqtSignal(QFocusEvent)
    
    def __init__(self, parent = ...):
        super().__init__(parent)
    
    def focusInEvent(self, e):
        self.focusIn.emit(e)
        return super().focusInEvent(e)
    
    def focusOutEvent(self, e):
        self.focusOut.emit(e)
        return super().focusOutEvent(e)