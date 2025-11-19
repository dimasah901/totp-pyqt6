from PyQt6.QtWidgets import (QApplication, QWidget, QTableWidgetItem,
                             QDialogButtonBox)
from PyQt6.QtCore import (QThread, pyqtSignal, QCoreApplication, QTimer,
                          QSettings)
from tab_ui import Ui_Tab
import encsqlite3
import totp
import datetime
import time
from pyzbar.pyzbar import decode
from PIL import Image, UnidentifiedImageError
from urllib.parse import urlparse, parse_qs, unquote
from offsettimer import DelayedTimer


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


class Tab(QWidget):
    exit = pyqtSignal()
    entry_available = pyqtSignal(bool, bool)
    save_state = pyqtSignal(bool)
    db_available = pyqtSignal(bool, bool)

    def __init__(self, dbpath, newdb=False):
        super().__init__()
        # bind ui actions
        self.ui = Ui_Tab()
        self.ui.setupUi(self)
        self.ui.pw_bts.rejected.connect(lambda: self.exit.emit())
        self.ui.pw_edit.returnPressed.connect(self.unlock_db)
        self.ui.pw_bts.accepted.connect(self.unlock_db)
        self.ui.new_bts_2.rejected.connect(lambda: self.exit.emit())
        self.ui.new_bts_2.accepted.connect(self.new_db)
        self.ui.new_pw_1.returnPressed.connect(self.new_db)
        self.ui.new_pw_2.returnPressed.connect(self.new_db)
        self.ui.new_bts.clicked.connect(self.new_qr_step)
        self.dbpath = dbpath
        self.ui.pw_error.hide()
        self.ui.new_error_2.hide()
        self.unsaved_changes = False
        # if the db is new, open a different screen
        if newdb:
            self.ui.pages.setCurrentIndex(4)
        else:
            self.ui.pages.setCurrentIndex(0)
        self.current_id = None
        self.loaded = False
        self.settings = QSettings("PyQT6", "Authenticator")
        self.autosave_timer = QTimer(self)
        self.autosave_timer.timeout.connect(self.save)
        self.autosave_timer.setSingleShot(True)

    def load_ui(self):
        self.ui.pw_error.hide()
        self.ui.pages.setCurrentIndex(1)
        self.ui.table_widget.verticalHeader().setVisible(False)
        self.ui.table_widget.setColumnWidth(0, 300)
        self.ui.table_widget.hideColumn(2)
        self.ui.table_widget.currentCellChanged.connect(self.tablewidget_cell)
        self.ui.table_widget.doubleClicked.connect(self.tablewidget_edit)
        # oldev = self.ui.table_widget.focusOutEvent
        # self.ui.table_widget.focusOutEvent =
        #     lambda *a: oldev(*a) or self.tablewidget_focusout()

        self.ui.edit_bts.clicked.connect(self.editor_button)

        self.update_table()

        self.entry_available.emit(True, False)
        self.db_available.emit(True, True)

    def go_back(self):
        self.ui.pages.setCurrentIndex(1)
        self.entry_available.emit(True, self.ui.table_widget.currentRow() > -1)

    def unsave(self):
        self.unsaved_changes = True
        self.save_state.emit(False)
        if self.settings.value("editor/autosave", True, bool):
            self.autosave_timer.stop()
            self.autosave_timer.start(
                self.settings.value("editor/autosave_delay", 0, int))

    def new_qr_step(self, button):
        match self.sender().buttonRole(button):
            case QDialogButtonBox.ButtonRole.YesRole:
                # user said they have a picture
                try:
                    qrdata = self.pull_qr_from_clipboard()
                    self.ui.pages.setCurrentIndex(2)
                    self.ui.edit_error.hide()
                    self.current_id = None

                    self.ui.edit_title.setText(
                        unquote(str(qrdata[0], encoding='ascii')))

                    self.ui.edit_algo.setCurrentText(
                        str(qrdata[1].get(b'algorithm', [b'SHA1'])[0], encoding='ascii').upper())

                    self.ui.edit_step.setValue(
                        int(str(qrdata[1].get(b'period', [b'30'])[0], encoding='ascii')))

                    self.ui.edit_size.setValue(
                        int(str(qrdata[1].get(b'digits', [b'6'])[0], encoding='ascii')))

                    self.ui.edit_origin.setDateTime(
                        datetime.datetime.fromtimestamp(0))

                    self.ui.edit_secret.setText(
                        str(qrdata[1].get(b'secret', [b''])[0], encoding='ascii'))

                    self.ui.edit_notes.document().setPlainText("")
                except UnidentifiedImageError:
                    # unable to parse the image
                    self.ui.new_error.show()
                    self.ui.new_error.setText("No image was provided")
                except Exception as ex:
                    # something else about the qr decoder
                    self.ui.new_error.show()
                    self.ui.new_error.setText(str(ex))
            case QDialogButtonBox.ButtonRole.NoRole:
                # user does not have a qr code
                self.ui.pages.setCurrentIndex(2)
                self.ui.edit_error.hide()
                self.current_id = None

                self.ui.edit_title.setText("")
                self.ui.edit_algo.setCurrentText("SHA1")
                self.ui.edit_step.setValue(30)
                self.ui.edit_size.setValue(6)
                self.ui.edit_origin.setDateTime(
                    datetime.datetime.fromtimestamp(0))
                self.ui.edit_secret.setText("")
                self.ui.edit_notes.document().setPlainText("")
            case QDialogButtonBox.ButtonRole.RejectRole:
                self.go_back()

    letters_set = set('abcdefghijklmnopqrstuvwxyz')
    digits_set = set('0123456789')

    def new_db(self):
        if self.ui.new_pw_1.text() != self.ui.new_pw_2.text():
            self.ui.new_error_2.show()
            self.ui.new_error_2.setText(
                self.tr("The passwords do not match!"))
            return
        if len(self.ui.new_pw_1.text()) < 16:
            self.ui.new_error_2.show()
            self.ui.new_error_2.setText(
                self.tr("The password is shorter than 16 characters!"))
            return
        charset = set(self.ui.new_pw_1.text().lower())
        if len(self.ui.new_pw_1.text()) < 28 \
                and len(charset.difference(self.digits_set)) == 0:
            self.ui.new_error_2.show()
            self.ui.new_error_2.setText(
                self.tr("Your password only consists of digits! "
                        "Make sure the password is at least 28 digits long or "
                        "use other characters too."))
            return
        self.ui.new_error_2.hide()
        self.enc = encsqlite3.EncryptedSQLite3(
            self.dbpath, bytes(self.ui.new_pw_1.text(), encoding='utf8'), True)
        self.db_cursor = self.enc.db.cursor()
        # init the keys table
        self.db_cursor.execute(
            "CREATE TABLE IF NOT EXISTS keys"
            "(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, algorithm TEXT,"
            "step INTEGER, size INTEGER, origin INTEGER, secret TEXT, notes TEXT)"
        )
        # delete the password for safety
        self.ui.pw_edit.setText("")
        self.load_ui()
        self.loaded = True

    def unlock_db(self):
        self.ui.pw_bts.setEnabled(False)
        self.ui.pw_edit.setEnabled(False)
        self.ui.pw_error.hide()
        self.pw_focused = self.ui.pw_edit.hasFocus()

        self.loader = LoadThread(
            self.dbpath, bytes(self.ui.pw_edit.text(), encoding='utf8'))
        self.loader.result.connect(self.loader_response)
        # delay the decrypting to let the ui update
        QTimer.singleShot(10, self.loader.run)

    def loader_response(self, db):
        if isinstance(db, encsqlite3.EncryptedSQLite3):
            self.enc = db
            self.db_cursor = self.enc.db.cursor()
            # make sure the keys table is there
            self.db_cursor.execute(
                "CREATE TABLE IF NOT EXISTS keys"
                "(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, algorithm TEXT,"
                "step INTEGER, size INTEGER, origin INTEGER, secret TEXT, notes TEXT)"
            )
            # delete the password for safety
            self.ui.pw_edit.setText("")
            self.load_ui()
            self.loaded = True
        else:
            # failed to decrypt
            self.ui.pw_error.show()
            self.ui.pw_error.setText(
                self.tr("Error while reading the database: {}. "
                        "The password you entered is incorrect, "
                        "or the database is corrupted.").format(type(db).__name__))
            self.ui.pw_bts.setEnabled(True)
            self.ui.pw_edit.setEnabled(True)
            if self.pw_focused:
                self.ui.pw_edit.setFocus()
        self.loader.result.disconnect()
        del self.loader

    def tablewidget_cell(self, row, column):
        # different cell focused
        self.entry_available.emit(True, row > -1)

    def tablewidget_edit(self):
        # cell double-clicked
        self.edit_entry()

    table_timers: list[DelayedTimer] = []

    def update_table(self):
        # delete current timers
        for timer in self.table_timers:
            timer.stop()
            timer.timeout.disconnect()
        self.table_timers = []
        data = self.db_cursor.execute("SELECT * FROM keys").fetchall()
        self.ui.table_widget.setRowCount(len(data))
        for row, entry in enumerate(data):
            self.ui.table_widget.setItem(row, 0,
                                         QTableWidgetItem(str(entry[1])))
            self.ui.table_widget.setItem(row, 2,
                                         QTableWidgetItem(str(entry[0])))
            self.update_entry(row, entry)
            # create an update timer
            timer = DelayedTimer(self)
            timer.timeout.connect(
                (lambda r, e: lambda: self.update_entry(r, e))(row, entry))
            timer.start(
                (entry[3] - (time.time() - entry[5]) % entry[3] + 1) * 1000,
                entry[3] * 1000)
            self.table_timers.append(timer)

    def update_entry(self, row, entry):
        # generate a new otp
        self.ui.table_widget.setItem(row, 1,
                                     QTableWidgetItem(
                                         str(
                                             totp.generate_totp(
                                                 totp.decode_b32_secret(entry[6]),
                                                 entry[5], entry[3], entry[4], entry[2])
                                             ).rjust(entry[4], '0')))

    def save(self):
        if self.loaded:
            self.enc.write()
            self.unsaved_changes = False
            self.save_state.emit(True)

    def save_as(self, path):
        if self.loaded:
            self.enc.path = path
            self.dbpath = path
            self.save()

    def save_db_backup(self, path):
        if self.loaded:
            oldpath = self.enc.path
            self.enc.path = path
            self.enc.write()
            self.enc.path = oldpath

    def editor_button(self, button):
        if self.sender().buttonRole(button) == QDialogButtonBox.ButtonRole.RejectRole:
            self.go_back()
            return
        try:
            # make sure the secret decodes
            totp.decode_b32_secret(self.ui.edit_secret.text())
        except Exception as ex:
            self.ui.edit_error.show()
            self.ui.edit_error.setText(
                self.tr("Unable to decode the secret provided: {}. "
                        "Make sure that the secret is Base32 encoded.").format(str(ex)))
            return

        if self.current_id is None:
            # a new entry
            self.db_cursor.execute(
                "INSERT INTO keys (name, algorithm, step, size, origin, secret, notes)"
                "VALUES (?, ?, ?, ?, ?, ?, ?)", (
                    self.ui.edit_title.text(), self.ui.edit_algo.currentText(),
                    self.ui.edit_step.value(), self.ui.edit_size.value(),
                    self.ui.edit_origin.dateTime().toSecsSinceEpoch(),
                    self.ui.edit_secret.text(), self.ui.edit_notes.document().toPlainText()
                ))
        else:
            # an existing entry
            self.db_cursor.execute(
                "UPDATE keys "
                "SET name = ?, algorithm = ?, step = ?, size = ?, origin = ?, secret = ?, notes = ? "
                "WHERE id = ?",
                (
                    self.ui.edit_title.text(), self.ui.edit_algo.currentText(),
                    self.ui.edit_step.value(), self.ui.edit_size.value(),
                    self.ui.edit_origin.dateTime().toSecsSinceEpoch(),
                    self.ui.edit_secret.text(), self.ui.edit_notes.document().toPlainText(),
                    self.current_id,
                ))
        self.enc.db.commit()
        self.update_table()
        self.unsave()
        self.go_back()

    def new_entry(self):
        if self.loaded:
            self.ui.new_error.hide()
            self.ui.pages.setCurrentIndex(3)
            self.entry_available.emit(False, False)

    def edit_entry(self):
        if self.loaded and self.ui.table_widget.currentRow() > -1:
            self.ui.pages.setCurrentIndex(2)
            self.ui.edit_error.hide()
            self.current_id = int(
                self.ui.table_widget.item(self.ui.table_widget.currentRow(), 2).text())

            data = self.db_cursor.execute(
                "SELECT * FROM keys WHERE id = ?", (self.current_id,)).fetchone()

            # fill fields with existing data
            self.ui.edit_title.setText(data[1])
            self.ui.edit_algo.setCurrentText(data[2])
            self.ui.edit_step.setValue(data[3])
            self.ui.edit_size.setValue(data[4])
            self.ui.edit_origin.setDateTime(datetime.datetime.fromtimestamp(data[5]))
            self.ui.edit_secret.setText(data[6])
            self.ui.edit_notes.document().setPlainText(data[7])
            # hide entry actions
            self.entry_available.emit(False, False)

    def delete_entry(self):
        if self.loaded and self.ui.table_widget.currentRow() > -1:
            id = int(self.ui.table_widget.item(self.ui.table_widget.currentRow(), 2).text())
            data = self.db_cursor.execute("DELETE FROM keys WHERE id = ?", (id,)).fetchone()
            self.update_table()
            self.entry_available.emit(True, self.ui.table_widget.currentRow() > -1)
            self.unsave()

    def copy_entry(self):
        if self.loaded and self.ui.table_widget.currentRow() > -1:
            id = int(self.ui.table_widget.item(self.ui.table_widget.currentRow(), 2).text())
            entry = self.db_cursor.execute("SELECT * FROM keys WHERE id = ?", (id,)).fetchone()
            # generate an otp and write it to the clipboard
            QApplication.clipboard().setText(
                str(
                    totp.generate_totp(
                        totp.decode_b32_secret(entry[6]),
                        entry[5], entry[3], entry[4], entry[2])
                    ).rjust(entry[4], '0'))

    def pull_qr_from_clipboard(self):
        # pull an image
        image = QApplication.clipboard().pixmap()
        converted = Image.fromqpixmap(image)
        decoded = decode(converted)
        if len(decoded) > 0:
            # found a qr code
            url = urlparse(decoded[0].data)
            if url.scheme == b'otpauth' and url.netloc == b'totp':
                # valid scheme and location
                qs = parse_qs(url.query)
                QApplication.clipboard().clear()
                return (url.path[1:], qs)
            else:
                raise Exception('Invalid scheme')
        else:
            raise Exception('No QR codes are in the image')

    def refresh(self):
        self.update_table()
