#include "InteractPanel.hpp"

InteractPanel::InteractPanel(QWidget *parent)
    : PanelContainer("互动玩法", parent)
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