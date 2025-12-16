#include "ScenePanel.hpp"
#include <QGridLayout>
#include <QButtonGroup>

ScenePanel::ScenePanel(QWidget *parent)
	: PanelContainer("场景", parent)
	, m_currentSceneIndex(0)
{
	initUI();
}

ScenePanel::~ScenePanel()
{
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
    // TODO 场景按钮
    setupSceneButtons();
    m_addSceneButton = new QPushButton("+");
    m_addSceneButton->setFixedSize(24, 24);
    connect(m_addSceneButton, &QPushButton::clicked, this, &ScenePanel::onAddSceneButtonClicked);
    m_sceneGridLayout->addWidget(m_addSceneButton, 2, 1); // 添加"+"按钮到第二行第二列
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

    // 创建底部"添加直播素材"按钮
    QWidget *addSourceButtonContainer = new QWidget(contentWidget);
    addSourceButtonContainer->setFixedHeight(30);
    addSourceButtonContainer->setStyleSheet("QWidget { background: rgba(0, 0, 0, 0.2);; }");
    QHBoxLayout *addSourceButtonLayout = new QHBoxLayout(addSourceButtonContainer);
    addSourceButtonLayout->setContentsMargins(10, 0, 10, 0);
    addSourceButtonLayout->setSpacing(0);
    m_addSourceButton = new QPushButton("添加直播素材", contentWidget);
    m_addSourceButton->setProperty("transparent_btn", true);
    m_addSourceButton->setStyleSheet("QPushButton { font-size: 14px; }");
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
    addSceneButton("场景一", 0, 0);
    addSceneButton("场景二", 0, 1);
    addSceneButton("场景三", 0, 2);
    addSceneButton("场景七", 1, 0);
    addSceneButton("场景八", 1, 1);
    addSceneButton("场景九", 1, 2);
    addSceneButton("场景十", 2, 0);

    if (!m_sceneButtons.isEmpty()) {
        selectScene(0);
    }
}

void ScenePanel::addSceneButton(const QString &name, int row, int col)
{
    QPushButton *sceneButton = new QPushButton(name);
    sceneButton->setFixedSize(65, 24);
    sceneButton->setCheckable(true);
    sceneButton->setProperty("scene_btn", true);

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
    QString sceneName = QString("场景%1").arg(ScenePanel::getChineseNumber(totalButtons + 1));
    addSceneButton(sceneName, row, col);
    
    // 移动"+"按钮到下一个位置
    m_sceneGridLayout->removeWidget(m_addSceneButton);
    int nextRow = (totalButtons + 1) / 3;
    int nextCol = (totalButtons + 1) % 3;
    m_sceneGridLayout->addWidget(m_addSceneButton, nextRow, nextCol);
    
    // 选中新添加的场景
    selectScene(totalButtons);
}

QString ScenePanel::getChineseNumber(int number)
{
    static const QStringList chineseNumbers = {
        "", "一", "二", "三", "四", "五", "六", "七", "八", "九", "十"
    };
    
    if (number <= 10) {
        return chineseNumbers[number];
    } else {
        return QString::number(number);
    }
}

void ScenePanel::onAddSourceButtonClicked()
{
    // TODO: 添加直播素材的逻辑
}

void ScenePanel::onSceneButtonClicked(int id)
{
    selectScene(id);
    // TODO: 切换场景内容的逻辑
}

void ScenePanel::onBroadcastButtonClicked()
{
    // TODO 导播按钮点击事件
}

void ScenePanel::onClearSourceButtonClicked()
{
    // TODO: 清空直播素材的逻辑
}