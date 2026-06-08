#include "mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent) {
    setWindowTitle(QStringLiteral("AntivirusMVP 1.0.0"));
    resize(800, 600);
}

MainWindow::~MainWindow() {
}
