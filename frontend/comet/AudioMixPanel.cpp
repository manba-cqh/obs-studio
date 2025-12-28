#include "AudioMixPanel.hpp"

AudioMixPanel::AudioMixPanel(QWidget *parent)
    : PanelContainer(parent)
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