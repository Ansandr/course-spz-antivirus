#include "mainwindow.h"

#include <QLabel>
#include <QTabWidget>
#include <QVBoxLayout>
#include <QWidget>

namespace {
QWidget* makePlaceholderTab(const QString& title) {
    auto* page = new QWidget;
    auto* layout = new QVBoxLayout(page);
    auto* label = new QLabel(QStringLiteral("Вкладка \"") + title + QStringLiteral("\" буде реалізована в наступних User Stories."));
    label->setWordWrap(true);
    layout->addStretch();
    layout->addWidget(label);
    layout->addStretch();
    return page;
}
}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent) {
    setWindowTitle(QStringLiteral("AntivirusMVP 1.0.0"));
    setMinimumSize(800, 600);
    resize(1000, 700);
    buildUi();
}

MainWindow::~MainWindow() {
}

void MainWindow::buildUi() {
    m_tabs = new QTabWidget(this);
    m_tabs->addTab(makePlaceholderTab(QStringLiteral("Сканування")), QStringLiteral("Сканування"));
    m_tabs->addTab(makePlaceholderTab(QStringLiteral("Процеси")), QStringLiteral("Процеси"));
    m_tabs->addTab(makePlaceholderTab(QStringLiteral("Карантин")), QStringLiteral("Карантин"));
    m_tabs->addTab(makePlaceholderTab(QStringLiteral("Журнал")), QStringLiteral("Журнал"));
    m_tabs->addTab(makePlaceholderTab(QStringLiteral("Налаштування")), QStringLiteral("Налаштування"));

    setCentralWidget(m_tabs);
}
