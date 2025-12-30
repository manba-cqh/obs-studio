#pragma once

#include <obs.hpp>
#include <QScrollArea>
#include <QVBoxLayout>
#include <QWidget>
#include <vector>

#include "PanelContainer.hpp"

class VolControl;

class AudioMixPanel : public PanelContainer
{
    Q_OBJECT
    
public:
    AudioMixPanel(QWidget *parent = nullptr);
    ~AudioMixPanel();
    
    void updateAudioSources();
    
private:
    void initUI();
    void clearVolumeControls();
    void addAudioSource(OBSSource source);
    bool isAudioSource(OBSSource source);
    
private:
    void onSceneChanged();
    
private:
    QScrollArea *m_scrollArea;
    QWidget *m_contentWidget;
    QVBoxLayout *m_contentLayout;
    std::vector<VolControl*> m_volumeControls;
};