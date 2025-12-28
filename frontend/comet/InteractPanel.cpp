#include "InteractPanel.hpp"

InteractPanel::InteractPanel(QWidget *parent)
    : PanelContainer(parent)
{
    initUI();
}

InteractPanel::~InteractPanel()
{
}

void InteractPanel::initUI()
{
    setContentWidget(new QWidget(this));
}