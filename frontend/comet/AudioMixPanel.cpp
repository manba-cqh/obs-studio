#include "AudioMixPanel.hpp"
#include <widgets/OBSBasic.hpp>
#include <widgets/VolControl.hpp>
#include <obs-frontend-api.h>
#include <QScrollArea>
#include <QVBoxLayout>
#include <QWidget>
#include <QFrame>

#include "tools.hpp"

AudioMixPanel::AudioMixPanel(QWidget *parent)
    : PanelContainer(parent)
{
    initUI();
    updateAudioSources();
    
    // 监听场景变化
    obs_frontend_add_event_callback([](enum obs_frontend_event event, void *param) {
        AudioMixPanel *panel = static_cast<AudioMixPanel*>(param);
        if (event == OBS_FRONTEND_EVENT_SCENE_CHANGED) {
            // 直接调用，避免使用 QMetaObject::invokeMethod（会导致元类型冲突）
            panel->updateAudioSources();
        }
    }, this);
}

AudioMixPanel::~AudioMixPanel()
{
    clearVolumeControls();
}

void AudioMixPanel::initUI()
{
    // 创建滚动区域
    m_scrollArea = new QScrollArea(this);
    m_scrollArea->setWidgetResizable(true);
    m_scrollArea->setFrameShape(QFrame::NoFrame);
    m_scrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    
    // 创建内容容器
    m_contentWidget = new QWidget();
    m_contentLayout = new QVBoxLayout(m_contentWidget);
    m_contentLayout->setContentsMargins(0, 0, 0, 0);
    m_contentLayout->setSpacing(0);
    m_contentLayout->addStretch();
    
    m_scrollArea->setWidget(m_contentWidget);
    setContentWidget(m_scrollArea);

    m_audioSettingButton = new QPushButton(this);
    m_audioSettingButton->setFixedSize(24, 24);
    m_audioSettingButton->setStyleSheet(BUTTON_QSS_STYLE("setting.png", "setting_hover.png", "setting_hover.png"));
}

void AudioMixPanel::updateAudioSources()
{
    clearVolumeControls();
    
    OBSBasic *main = OBSBasic::Get();
    if (!main) {
        return;
    }
    
    OBSScene scene = main->GetCurrentScene();
    if (!scene) {
        return;
    }
    
    // 枚举场景中的所有项，查找音频源
    struct EnumData {
        AudioMixPanel *panel;
    } enumData = {this};
    
    auto enumItem = [](obs_scene_t *, obs_sceneitem_t *item, void *param) -> bool {
        EnumData *data = static_cast<EnumData*>(param);
        OBSSource source = obs_sceneitem_get_source(item);
        if (data->panel->isAudioSource(source)) {
            data->panel->addAudioSource(source);
        }
        return true;
    };
    
    obs_scene_enum_items(scene, enumItem, &enumData);
    
    // 添加全局音频设备（桌面音频和麦克风）
    OBSSource desktopAudio = obs_get_output_source(1);
    if (desktopAudio && isAudioSource(desktopAudio)) {
        addAudioSource(desktopAudio);
    }
    
    OBSSource micAudio = obs_get_output_source(3);
    if (micAudio && isAudioSource(micAudio)) {
        addAudioSource(micAudio);
    }
}

void AudioMixPanel::clearVolumeControls()
{
    for (VolControl *vol : m_volumeControls) {
        m_contentLayout->removeWidget(vol);
        delete vol;
    }
    m_volumeControls.clear();
}

void AudioMixPanel::addAudioSource(OBSSource source)
{
    if (!source || obs_source_removed(source)) {
        return;
    }
    
    // 检查是否已经存在
    for (VolControl *vol : m_volumeControls) {
        if (vol->GetSource() == source) {
            return;
        }
    }
    
    // 创建音量控制
    VolControl *volControl = new VolControl(source, false, false);
    m_volumeControls.push_back(volControl);
    
    // 插入到布局中（在 stretch 之前）
    int insertIndex = m_contentLayout->count() - 1;
    m_contentLayout->insertWidget(insertIndex, volControl);
}

bool AudioMixPanel::isAudioSource(OBSSource source)
{
    if (!source || obs_source_removed(source)) {
        return false;
    }
    
    uint32_t flags = obs_source_get_output_flags(source);
    return (flags & OBS_SOURCE_AUDIO) != 0;
}

void AudioMixPanel::onSceneChanged()
{
    updateAudioSources();
}