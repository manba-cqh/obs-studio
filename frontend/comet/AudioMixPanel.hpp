#pragma once

#include "PanelContainer.hpp"

class AudioMixPanel : public PanelContainer
{
    Q_OBJECT
    
public:
    AudioMixPanel(QWidget *parent = nullptr);
    ~AudioMixPanel();
private:
    void initUI();
};