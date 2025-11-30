from PyQt6.QtWidgets import (QApplication, QMainWindow, QPushButton,
                             QFileDialog, QMessageBox, QDialog)
from PyQt6.QtCore import (QThread, pyqtSignal, QDir, QLibraryInfo,
                          QTimer, QSettings, QUrl, QTranslator, QLocale)
from main_ui import Ui_MainWindow
import encsqlite3
import sys
import tab
import os
from functools import partial
from about_ui import Ui_Dialog


class LoadThread(QThread):
    result = pyqtSignal(object)

    def __init__(self, path, password):
        super().__init__()
        self.path = path
        self.password = password

    def run(self):
        try:
            db = encsqlite3.EncryptedSQLite3(self.path, self.password)
            self.result.emit(db)
        except Exception as ex:
            self.result.emit(ex)


def get_current_locale():
    if QLocale().language() == QLocale.Language.Russian:
        return "ru"
    return "en"


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.tab = None

        # bind all actions
        self.ui.action_new_db.triggered.connect(self.new_db)
        self.ui.action_open_db.triggered.connect(self.open_db)
        self.ui.action_save_db.triggered.connect(self.save_db)
        self.ui.action_save_db_as.triggered.connect(self.save_db_as)
        self.ui.action_save_db_backup.triggered.connect(self.save_db_backup)
        self.ui.action_close_db.triggered.connect(self.close_db)

        self.ui.action_new_entry.triggered.connect(self.new_entry)
        self.ui.action_edit_entry.triggered.connect(self.edit_entry)
        self.ui.action_delete_entry.triggered.connect(self.delete_entry)
        self.ui.action_copy.triggered.connect(self.copy_entry)

        self.ui.action_settings.triggered.connect(self.open_settings)
        self.ui.action_refresh.triggered.connect(self.refresh)

        self.ui.action_about.triggered.connect(self.about)
        self.ui.action_help.triggered.connect(self.open_help)
        self.ui.exit_help.clicked.connect(self.reject_settings)

        self.ui.new_database.clicked.connect(self.new_db)
        self.ui.open_database.clicked.connect(self.open_db)

        self.ui.settings_bts.accepted.connect(self.accept_settings)
        self.ui.settings_bts.rejected.connect(self.reject_settings)

        self.settings = QSettings("PyQT6", "Authenticator")

        self.ui.tabs.setCurrentIndex(0)

        self.entry_available(False, False)
        self.db_available(False, False)

    def help_anchor(self, path: QUrl):
        # loads the file and writes it to the help browser
        try:
            with open(os.path.abspath(os.path.dirname(__file__))+"/docs/"+get_current_locale()+"/"+path.path(), 'r', encoding='utf8') as file:
                self.ui.help_browser.document().setHtml(file.read())
        except FileNotFoundError:
            self.ui.help_browser.document().setPlainText(
                self.tr("File is unavailable."))

    def open_help(self):
        # lock all actions
        self.ui.action_settings.setEnabled(False)
        self.ui.action_help.setEnabled(False)
        db_avb = self.db_availability
        self.db_available(False, False, False)
        self.db_availability = db_avb
        ent_avb = self.entry_availability
        self.entry_available(False, False)
        self.entry_availability = ent_avb
        # switch pages
        self.ui.tabs.setCurrentIndex(2)
        self.ui.help_browser.anchorClicked.connect(self.help_anchor)
        # load the main page
        self.help_anchor(QUrl("index.html"))

    def about(self):
        # opens an about dialog
        dialog = QDialog(self)
        dialog.ui = Ui_Dialog()
        dialog.ui.setupUi(dialog)
        dialog.exec()

    def new_db(self, button=None):
        if isinstance(button, QPushButton):
            # called by the button click listener
            match self.sender().buttonRole(button):
                case QMessageBox.ButtonRole.DestructiveRole:
                    QTimer.singleShot(0, self._new_db)
                case QMessageBox.ButtonRole.AcceptRole:
                    self.tab.save()
                    QTimer.singleShot(0, self._new_db)
        elif self.tab is not None and self.tab.unsaved_changes:
            # unsaved database, ask user to save
            message = QMessageBox(self)
            message.setWindowTitle(self.tr("Save changes?"))
            message.setText(
                self.tr("The database was modified.\nSave changes?"))
            message.addButton(
                QPushButton('Close without Saving'), QMessageBox.ButtonRole.DestructiveRole)
            message.addButton(
                QPushButton('Cancel'), QMessageBox.ButtonRole.RejectRole)
            message.addButton(
                QPushButton('Save'), QMessageBox.ButtonRole.AcceptRole)
            message.buttonClicked.connect(self.new_db)
            message.exec()
        else:
            # creates a new database
            self._new_db()

    def launch_tab(self, *args):
        self.tab = tab.Tab(*args)
        self.tab.exit.connect(self.close_db)
        self.tab.entry_available.connect(self.entry_available)
        self.tab.save_state.connect(self.set_save_state)
        self.tab.db_available.connect(self.db_available)
        # show the new tab
        self.ui.tabs.addWidget(self.tab)
        self.ui.tabs.setCurrentIndex(3)
        # reset ui state
        self.entry_available(False, False)
        self.db_available(True, False)
        # change window title
        self.setWindowTitle(
            self.tr("Authenticator - {}")
            .format(self.tab.dbpath.split('/')[-1]))

    def close_tab(self):
        if self.tab is not None:
            # disconnect all signals
            self.tab.exit.disconnect()
            self.tab.entry_available.disconnect()
            self.tab.save_state.disconnect()
            self.tab.db_available.disconnect()
            # remove the tab widget
            self.ui.tabs.removeWidget(self.tab)
            self.ui.tabs.setCurrentIndex(0)
            del self.tab
            self.tab = None
            # reset ui state
            self.entry_available(False, False)
            self.db_available(False, False)
        # clear window title
        self.setWindowTitle(self.tr("Authenticator"))

    def open_settings(self):
        # lock all actions
        self.ui.action_settings.setEnabled(False)
        db_avb = self.db_availability
        self.db_available(False, False, False)
        self.db_availability = db_avb
        ent_avb = self.entry_availability
        self.entry_available(False, False)
        self.entry_availability = ent_avb
        # switch pages
        self.ui.tabs.setCurrentIndex(1)
        # pull current settings
        self.ui.settings_autosave.setChecked(
            self.settings.value("editor/autosave", True, bool))
        self.ui.settings_autosave_delay.setValue(
            self.settings.value("editor/autosave_delay", 0, int)/1000)

    def accept_settings(self):
        # common code for switching back
        self.reject_settings()
        # write settings
        self.settings.setValue(
            "editor/autosave", self.ui.settings_autosave.isChecked())
        self.settings.setValue(
            "editor/autosave_delay", int(self.ui.settings_autosave_delay.value()*1000))

    def reject_settings(self):
        self.ui.action_settings.setEnabled(True)
        self.ui.action_help.setEnabled(True)
        if self.tab is None:
            self.ui.tabs.setCurrentIndex(0)
        else:
            self.ui.tabs.setCurrentIndex(3)
        # unlock actions
        self.db_available(*self.db_availability)
        self.entry_available(*self.entry_availability)

    def entry_available(self, fornew, forsel):
        # (un)lock the entry actions
        self.ui.action_new_entry.setEnabled(fornew)
        self.ui.action_delete_entry.setEnabled(forsel)
        self.ui.action_edit_entry.setEnabled(forsel)
        self.ui.action_copy.setEnabled(forsel)
        self.entry_availability = (fornew, forsel)

    def db_available(self, available, unlocked, any=True):
        # (un)lock the database actions
        self.ui.action_new_db.setEnabled(any)
        self.ui.action_open_db.setEnabled(any)
        self.ui.action_save_db.setEnabled(unlocked)
        self.ui.action_save_db_as.setEnabled(unlocked)
        self.ui.action_save_db_backup.setEnabled(unlocked)
        self.ui.action_close_db.setEnabled(available)
        self.ui.action_refresh.setEnabled(unlocked)
        self.db_availability = (available, unlocked)

    def set_save_state(self, state):
        # changes the '*' in the title
        if self.tab is not None:
            self.setWindowTitle(
                self.tr("Authenticator - {}")
                .format(self.tab.dbpath.split('/')[-1] + ('' if state else '*')))

    def _new_db(self):
        # picks a file path and launches a new tab
        file, ok = QFileDialog.getSaveFileName(self, "New database", None, "Database (*.encdb)")
        if ok:
            if self.tab is not None:
                self.close_tab()
            self.launch_tab(file, True)

    def open_db(self, button=None):
        if isinstance(button, QPushButton):
            # called by the button click listener
            match self.sender().buttonRole(button):
                case QMessageBox.ButtonRole.DestructiveRole:
                    QTimer.singleShot(0, self._open_db)
                case QMessageBox.ButtonRole.AcceptRole:
                    self.tab.save()
                    QTimer.singleShot(0, self._open_db)
        elif self.tab is not None and self.tab.unsaved_changes:
            # unsaved database, ask user to save
            message = QMessageBox(self)
            message.setWindowTitle(self.tr("Save changes?"))
            message.setText(
                self.tr("The database was modified.\nSave changes?"))
            message.addButton(
                QPushButton('Close without Saving'), QMessageBox.ButtonRole.DestructiveRole)
            message.addButton(
                QPushButton('Cancel'), QMessageBox.ButtonRole.RejectRole)
            message.addButton(
                QPushButton('Save'), QMessageBox.ButtonRole.AcceptRole)
            message.buttonClicked.connect(self.open_db)
            message.exec()
        else:
            # opens a database
            self._open_db()

    def _open_db(self):
        # picks a file path and launches a new tab
        file, ok = QFileDialog.getOpenFileName(self, "Open a database", None, "Database (*.encdb)")
        if ok:
            self.ui.tabs.removeWidget(self.tab)
            self.launch_tab(file)

    def save_db(self):
        # if a tab is open, save it
        if self.tab is not None:
            self.tab.save()

    def save_db_as(self):
        # if a tab is open, picks a file path and sends it to the tab
        if self.tab is not None:
            file, ok = QFileDialog.getSaveFileName(self, "Save database as", None, "Database (*.encdb)")
            if ok:
                self.tab.save_as(file)

    def save_db_backup(self):
        # if a tab is open, picks a file path and sends it to the tab
        if self.tab is not None:
            file, ok = QFileDialog.getSaveFileName(self, "Save database backup", None, "Database (*.encdb)")
            if ok:
                self.tab.save_db_backup(file)

    def close_db(self, button=None):
        if isinstance(button, QPushButton):
            # called by the button click listener
            match self.sender().buttonRole(button):
                case QMessageBox.ButtonRole.DestructiveRole:
                    self.close_tab()
                case QMessageBox.ButtonRole.AcceptRole:
                    self.tab.save()
                    self.close_tab()
        elif self.tab is not None:
            # unsaved database, ask user to save
            if self.tab.unsaved_changes:
                message = QMessageBox(self)
                message.setWindowTitle(self.tr("Save changes?"))
                message.setText(
                    self.tr("The database was modified.\nSave changes?"))
                message.addButton(
                    QPushButton('Close without Saving'), QMessageBox.ButtonRole.DestructiveRole)
                message.addButton(
                    QPushButton('Cancel'), QMessageBox.ButtonRole.RejectRole)
                message.addButton(
                    QPushButton('Save'), QMessageBox.ButtonRole.AcceptRole)
                message.buttonClicked.connect(self.close_db)
                message.exec()
            else:
                # closes the database
                self.close_tab()

    def closeEvent(self, event):
        if self.tab is not None and self.tab.unsaved_changes:
            # unsaved database, ask user to save before quitting
            message = QMessageBox(self)
            message.setWindowTitle(self.tr("Save changes?"))
            message.setText(
                self.tr("The database was modified.\nSave changes?"))
            message.addButton(
                QPushButton('Close without Saving'), QMessageBox.ButtonRole.DestructiveRole)
            message.addButton(
                QPushButton('Cancel'), QMessageBox.ButtonRole.RejectRole)
            message.addButton(
                QPushButton('Save'), QMessageBox.ButtonRole.AcceptRole)
            message.buttonClicked.connect(partial(self.window_close, event))
            message.exec()

    def window_close(self, event, button):
        # called by the closeEvent() message button click listener
        match self.sender().buttonRole(button):
            case QMessageBox.ButtonRole.DestructiveRole:
                event.accept()
            case QMessageBox.ButtonRole.AcceptRole:
                self.tab.save()
                event.accept()
            case QMessageBox.ButtonRole.RejectRole:
                event.ignore()

    def new_entry(self):
        # if a tab is open, pass the action
        if self.tab is not None:
            self.tab.new_entry()

    def edit_entry(self):
        # if a tab is open, pass the action
        if self.tab is not None:
            self.tab.edit_entry()

    def delete_entry(self):
        # if a tab is open, pass the action
        if self.tab is not None:
            self.tab.delete_entry()

    def copy_entry(self):
        # if a tab is open, pass the action
        if self.tab is not None:
            self.tab.copy_entry()

    def refresh(self):
        # if a tab is open, pass the action
        if self.tab is not None:
            self.tab.refresh()

    def retranslateUi(self):
        self.ui.retranslateUi()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    translator = QTranslator(app)
    #if translator.load(QLocale.system(), "locale.qm"):
    #    app.installTranslator(translator)
    #if translator.load(QLocale.system(), "", "", QDir("./").absolutePath()):
    #QLocale.setDefault(QLocale(QLocale.Language.Russian))
    if translator.load(QLocale(), "", "", os.path.abspath(os.path.dirname(__file__))):
        app.installTranslator(translator)
    ex = MainWindow()
    ex.show()
    # cProfile.run('sys.exit(app.exec())')
    sys.exit(app.exec())
