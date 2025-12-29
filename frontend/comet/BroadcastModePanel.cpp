#include "BroadcastModePanel.hpp"

BroadcastModePanel::BroadcastModePanel(QWidget *parent)
    : PanelContainer(parent)
{
    initUI();
}

BroadcastModePanel::~BroadcastModePanel()
{
}

void BroadcastModePanel::initUI()
{
    setContentWidget(new QWidget(this));
}