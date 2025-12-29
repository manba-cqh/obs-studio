#pragma once

#include "PanelContainer.hpp"

class BroadcastModePanel : public PanelContainer
{
    Q_OBJECT
    
public:
    BroadcastModePanel(QWidget *parent = nullptr);
    ~BroadcastModePanel();
private:
    void initUI();
};