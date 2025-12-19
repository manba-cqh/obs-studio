#include "AudioMixPanel.hpp"

AudioMixPanel::AudioMixPanel(QWidget *parent)
    : PanelContainer("混音器", parent)
{
    initUI();
}

AudioMixPanel::~AudioMixPanel()
{
}

void AudioMixPanel::initUI()
{
    setContentWidget(new QWidget(this));
}