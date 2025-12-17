#include "ScenePanel.hpp"
#include <QGridLayout>
#include <QButtonGroup>
#include <QFontMetrics>
#include <QCursor>

#include <obs-frontend-api.h>
#include <obs.hpp>
#include <widgets/OBSBasic.hpp>

ScenePanel::ScenePanel(QWidget *parent)
	: PanelContainer("场景", parent)
	, m_currentSceneIndex(0)
{
	initUI();
	// 注册 OBS 前端事件回调
	obs_frontend_add_event_callback(OBSFrontendEvent, this);
}

ScenePanel::~ScenePanel()
{
    // 移除 OBS 前端事件回调
    obs_frontend_remove_event_callback(OBSFrontendEvent, this);
    
    // 断开所有信号连接，避免在析构时触发回调
    if (m_sceneButtonGroup) {
        m_sceneButtonGroup->disconnect();
    }
    
    // 清理按钮列表
    m_sceneButtons.clear();
}

void ScenePanel::initUI()
{
   createHeaderOperWidget();
   createContentWidget();
}

void ScenePanel::createHeaderOperWidget()
{
    m_broadcastButton = new QPushButton();
    m_broadcastButton->setFixedSize(56, 24);
    m_broadcastButton->setText("导播");
    m_broadcastButton->setProperty("transparent_btn", true);
    m_broadcastButton->setStyleSheet("QPushButton { font-size: 12px; }");
    // TODO 设置导播按钮图标
    connect(m_broadcastButton, &QPushButton::clicked, this, &ScenePanel::onBroadcastButtonClicked);
    setHeaderOperWidget(m_broadcastButton);
}

void ScenePanel::createContentWidget()
{
    QWidget *contentWidget = new QWidget(this);
    QVBoxLayout *contentLayout = new QVBoxLayout(contentWidget);
    contentLayout->setContentsMargins(0, 0, 0, 0);
    contentLayout->setSpacing(5);

    // 创建场景按钮区域
    QWidget *sceneButtonsWidget = new QWidget(contentWidget);
    m_sceneGridLayout = new QGridLayout(sceneButtonsWidget);
    m_sceneGridLayout->setContentsMargins(0, 0, 0, 0);
    m_sceneGridLayout->setSpacing(5);

    m_sceneButtonGroup = new QButtonGroup(this);
    m_sceneButtonGroup->setExclusive(true);
    connect(m_sceneButtonGroup, QOverload<QAbstractButton *>::of(&QButtonGroup::buttonClicked), [this](QAbstractButton *button) {
        int id = m_sceneButtonGroup->id(button);
        onSceneButtonClicked(id);
    });
    m_addSceneButton = new QPushButton("+");
    m_addSceneButton->setFixedSize(24, 24);
    connect(m_addSceneButton, &QPushButton::clicked, this, &ScenePanel::onAddSceneButtonClicked);
    contentLayout->addWidget(sceneButtonsWidget);

    QWidget *separator = new QWidget(contentWidget);
    separator->setFixedHeight(1);
    separator->setStyleSheet("QWidget { background-color: rgba(255, 255, 255, 125); }");
    contentLayout->addWidget(separator);

    // 创建内容列表区域
    QWidget *listWidgetContainer = new QWidget(contentWidget);
    QVBoxLayout *listLayout = new QVBoxLayout(listWidgetContainer);
    listLayout->setContentsMargins(0, 0, 0, 0);
    listLayout->setSpacing(0);

    m_currentContentList = new QListWidget(listWidgetContainer);
    listLayout->addWidget(m_currentContentList);
    contentLayout->addWidget(listWidgetContainer);

    setupSceneButtons();

    // 创建底部"添加直播素材"按钮
    QWidget *addSourceButtonContainer = new QWidget(contentWidget);
    addSourceButtonContainer->setFixedHeight(30);
    addSourceButtonContainer->setStyleSheet("background: rgba(21, 21, 32, 1);");
    QHBoxLayout *addSourceButtonLayout = new QHBoxLayout(addSourceButtonContainer);
    addSourceButtonLayout->setContentsMargins(10, 0, 10, 0);
    addSourceButtonLayout->setSpacing(0);
    m_addSourceButton = new QPushButton("添加直播素材", contentWidget);
    m_addSourceButton->setProperty("transparent_btn", true);
    m_addSourceButton->setStyleSheet("QPushButton { font-size: 14px;  }");
    m_addSourceButton->setFixedSize(120, 24);
    connect(m_addSourceButton, &QPushButton::clicked, this, &ScenePanel::onAddSourceButtonClicked);
    addSourceButtonLayout->addWidget(m_addSourceButton);
    addSourceButtonLayout->addStretch();
    m_clearSourceButton = new QPushButton("清空", contentWidget);
    m_clearSourceButton->setProperty("transparent_btn", true);
    m_clearSourceButton->setStyleSheet("QPushButton { font-size: 14px; }");
    m_clearSourceButton->setFixedSize(42, 24);
    connect(m_clearSourceButton, &QPushButton::clicked, this, &ScenePanel::onClearSourceButtonClicked);
    addSourceButtonLayout->addWidget(m_clearSourceButton);
    contentLayout->addWidget(addSourceButtonContainer);

    setContentWidget(contentWidget);
}

void ScenePanel::setupSceneButtons()
{
    // 从 OBS 获取场景列表
    struct obs_frontend_source_list scenes = {0};
    obs_frontend_get_scenes(&scenes);

    // 为每个场景创建按钮
    int sceneCount = (int)scenes.sources.num;
    for (int i = 0; i < sceneCount; i++) {
        obs_source_t *source = scenes.sources.array[i];
        const char *sceneName = obs_source_get_name(source);
        
        int row = i / 3;
        int col = i % 3;
        addSceneButton(QString::fromUtf8(sceneName), row, col);
        
        obs_source_release(source);
    }

    // 释放场景列表
    obs_frontend_source_list_free(&scenes);

    // 更新"+"按钮位置
    if (m_addSceneButton) {
        m_sceneGridLayout->removeWidget(m_addSceneButton);
        int totalButtons = m_sceneButtons.size();
        int nextRow = totalButtons / 3;
        int nextCol = totalButtons % 3;
        m_sceneGridLayout->addWidget(m_addSceneButton, nextRow, nextCol);
    }

    if (!m_sceneButtons.isEmpty()) {
        onSceneButtonClicked(0);
    }
}

void ScenePanel::addSceneButton(const QString &name, int row, int col)
{
    QPushButton *sceneButton = new QPushButton();
    sceneButton->setFixedSize(65, 24);
    sceneButton->setCheckable(true);
    sceneButton->setProperty("scene_btn", true);
    
    // 计算文本宽度，如果超出按钮宽度则截断并添加省略号
    QFontMetrics fm(sceneButton->font());
    int buttonWidth = sceneButton->width();
    int textWidth = fm.horizontalAdvance(name);
    
    QString displayText = name;
    if (textWidth > buttonWidth - 10) { // 留出一些边距
        displayText = fm.elidedText(name, Qt::ElideRight, buttonWidth - 10);
    }
    sceneButton->setText(displayText);
    sceneButton->setToolTip(name); // 设置完整文本作为提示

    m_sceneButtonGroup->addButton(sceneButton, m_sceneButtons.size());
    m_sceneButtons.append(sceneButton);
    m_sceneGridLayout->addWidget(sceneButton, row, col);
}

void ScenePanel::selectScene(int index)
{
    for (QPushButton *button : m_sceneButtons) {
        button->setChecked(false);
    }
    if (index >= 0 && index < m_sceneButtons.size()) {
        m_currentSceneIndex = index;
        m_sceneButtons[index]->setChecked(true);
    }
}

void ScenePanel::onBroadcastButtonClicked()
{
    // TODO 导播按钮点击事件
}

void ScenePanel::onAddSceneButtonClicked()
{
    // 计算新场景的位置
    int totalButtons = m_sceneButtons.size();
    int row = totalButtons / 3;
    int col = totalButtons % 3;
    
    // 如果当前行已满，移动到下一行
    if (col == 0 && row > 0) {
        // 需要移动"+"按钮
        m_sceneGridLayout->removeWidget(m_addSceneButton);
        row++;
        col = 0;
    }
    
    // 添加新场景按钮
    QString sceneName = QString("场景%1").arg(totalButtons + 1);
    addSceneButton(sceneName, row, col);
    
    // 移动"+"按钮到下一个位置
    m_sceneGridLayout->removeWidget(m_addSceneButton);
    int nextRow = (totalButtons + 1) / 3;
    int nextCol = (totalButtons + 1) % 3;
    m_sceneGridLayout->addWidget(m_addSceneButton, nextRow, nextCol);
    
    // 选中新添加的场景
    selectScene(totalButtons);
}

void ScenePanel::onAddSourceButtonClicked()
{
    // 调用 OBS 原生的添加源功能
    OBSBasic *main = OBSBasic::Get();
    if (main) {
        main->AddSourcePopupMenu(QCursor::pos());
    }
}

void ScenePanel::onSceneButtonClicked(int id)
{
    selectScene(id);
    
    // 切换到对应的场景
    if (id >= 0 && id < m_sceneButtons.size()) {
        struct obs_frontend_source_list scenes = {0};
        obs_frontend_get_scenes(&scenes);
        
        if (id < (int)scenes.sources.num) {
            obs_source_t *source = scenes.sources.array[id];
            obs_frontend_set_current_scene(source);
            obs_source_release(source);
        }
        
        obs_frontend_source_list_free(&scenes);
    }
    
    // 更新当前场景的源列表
    updateCurrentSceneSources();
}

void ScenePanel::onClearSourceButtonClicked()
{
    // TODO: 清空直播素材的逻辑
}

void ScenePanel::updateCurrentSceneSources()
{
    if (!m_currentContentList) {
        return;
    }
    
    // 清空列表
    m_currentContentList->clear();
    
    // 获取当前场景
    OBSBasic *main = OBSBasic::Get();
    if (!main) {
        return;
    }
    
    OBSScene scene = main->GetCurrentScene();
    if (!scene) {
        return;
    }
    
    // 枚举场景中的所有项
    auto enumItem = [](obs_scene_t *, obs_sceneitem_t *item, void *param) -> bool {
        QListWidget *list = static_cast<QListWidget *>(param);
        
        obs_source_t *source = obs_sceneitem_get_source(item);
        if (!source || obs_source_removed(source)) {
            return true;
        }
        
        const char *sourceName = obs_source_get_name(source);
        if (sourceName) {
            QListWidgetItem *listItem = new QListWidgetItem(QString::fromUtf8(sourceName), list);
            list->addItem(listItem);
        }
        
        return true;
    };
    
    obs_scene_enum_items(scene, enumItem, m_currentContentList);
}

void ScenePanel::OBSFrontendEvent(enum obs_frontend_event event, void *ptr)
{
    ScenePanel *panel = static_cast<ScenePanel *>(ptr);
    if (!panel) {
        return;
    }
    
    switch (event) {
    case OBS_FRONTEND_EVENT_SCENE_CHANGED:
    case OBS_FRONTEND_EVENT_PREVIEW_SCENE_CHANGED:
        // 场景改变时更新源列表
        panel->updateCurrentSceneSources();
        break;
    case OBS_FRONTEND_EVENT_SCENE_LIST_CHANGED:
        // 场景列表改变时，重新设置场景按钮并更新源列表
        panel->setupSceneButtons();
        panel->updateCurrentSceneSources();
        break;
    default:
        break;
    }
}