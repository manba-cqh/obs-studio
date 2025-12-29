#include "PluginPanel.hpp"

PluginPanel::PluginPanel(QWidget *parent)
    : PanelContainer(parent)
{
    initUI();
}

PluginPanel::~PluginPanel()
{
}

void PluginPanel::initUI()
{
    setContentWidget(new QWidget(this));
}