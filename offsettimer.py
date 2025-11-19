from PyQt6.QtCore import QTimer, pyqtSignal, QObject


class DelayedTimer(QObject):
    _started = False
    timeout = pyqtSignal()
    _interval = 0

    def __init__(self, parent=...):
        super().__init__(parent)
        self._timer = QTimer(parent)
        self._timer.timeout.connect(self._fire)
        self._launch_timer = QTimer(parent)
        self._launch_timer.timeout.connect(self._startTimer)
        self._launch_timer.setSingleShot(True)
        # self._launch_timer.setTimerType(Qt.TimerType.PreciseTimer)
        # self._timer.setTimerType(Qt.TimerType.PreciseTimer)

    def _startTimer(self):
        self.timeout.emit()
        self._timer.start(self._interval)

    def _fire(self):
        self.timeout.emit()
        # print(f'time={time.time()}')

    def start(self, delay, interval):
        if not self._started:
            # print(f'delay={delay}, interval={interval}')
            self._started = True
            self._interval = int(interval)
            self._launch_timer.start(int(delay))

    def stop(self):
        self._started = False
        self._launch_timer.stop()
        self._timer.stop()
