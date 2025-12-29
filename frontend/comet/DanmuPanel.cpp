#include "DanmuPanel.hpp"

DanmuPanel::DanmuPanel(QWidget *parent)
    : PanelContainer(parent)
{
    initUI();
}

DanmuPanel::~DanmuPanel()
{
}

void DanmuPanel::initUI()
{
    setContentWidget(new QWidget(this));
}