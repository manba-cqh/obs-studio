#pragma once

#include "PanelContainer.hpp"

class PluginPanel : public PanelContainer
{
    Q_OBJECT
    
public:
    PluginPanel(QWidget *parent = nullptr);
    ~PluginPanel();
private:
    void initUI();
};