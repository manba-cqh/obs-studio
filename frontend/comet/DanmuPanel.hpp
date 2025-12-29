#pragma once

#include "PanelContainer.hpp"

class DanmuPanel : public PanelContainer
{
    Q_OBJECT
    
public:
    DanmuPanel(QWidget *parent = nullptr);
    ~DanmuPanel();
private:
    void initUI();
};