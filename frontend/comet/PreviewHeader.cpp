#include "PreviewHeader.hpp"
#include "tools/tools.hpp"

#include <widgets/OBSBasic.hpp>
#include <util/config-file.h>
#include <qt-wrappers.hpp>

#include <QIcon>

PreviewHeader::PreviewHeader(QWidget *parent)
	: QWidget(parent)
{
	initUI();
	loadCurrentPlatformInfo();
}

PreviewHeader::~PreviewHeader()
{
}

void PreviewHeader::initUI()
{
	setFixedHeight(42);
	setAttribute(Qt::WA_StyledBackground, true);
	setStyleSheet("PreviewHeader { background: transparent; }");

	m_layout = new QHBoxLayout(this);
	m_layout->setContentsMargins(0, 0, 0, 0);
	m_layout->setSpacing(0);

	// ===== 左侧：平台图标 + 状态点 + 状态文字 + 设置按钮 =====
	QWidget *leftWidget = new QWidget(this);
	leftWidget->setFixedHeight(42);
	leftWidget->setStyleSheet("QWidget { background: #222232; border-radius: 5px; }");
	QHBoxLayout *leftLayout = new QHBoxLayout(leftWidget);
	leftLayout->setContentsMargins(5, 0, 5, 0);
	leftLayout->setSpacing(6);

	m_platformIcon = new QLabel(this);
	m_platformIcon->setFixedSize(30, 30);
	m_platformIcon->setScaledContents(true);
	m_platformIcon->setStyleSheet("QLabel { background: transparent; border: none; }");
	leftLayout->addWidget(m_platformIcon);

	m_statusDot = new QLabel(this);
	m_statusDot->setFixedSize(8, 8);
	m_statusDot->setStyleSheet(
		"QLabel {"
		"    background-color: #FF3040;"
		"    border-radius: 4px;"
		"    border: none;"
		"}");
	leftLayout->addWidget(m_statusDot);

	m_statusLabel = new QLabel("未启用", this);
	m_statusLabel->setStyleSheet("QLabel { color: #AAABB8; font-size: 14px; background: transparent; border: none; }");
	leftLayout->addWidget(m_statusLabel);

	m_streamSettingBtn = new QPushButton(this);
	m_streamSettingBtn->setFixedSize(20, 20);
	m_streamSettingBtn->setStyleSheet(BUTTON_QSS_STYLE("setting.svg", "setting_hover.svg", "setting_hover.svg"));
	m_streamSettingBtn->setToolTip("推流设置");
	connect(m_streamSettingBtn, &QPushButton::clicked, this, [this]() { emit settingsRequested(3); });
	leftLayout->addWidget(m_streamSettingBtn);

	m_layout->addWidget(leftWidget);
	m_layout->addStretch();

	// ===== 右侧：横屏/竖屏切换 + 分隔符 + 设置 + 全屏 =====
	QWidget *rightWidget = new QWidget(this);
	rightWidget->setFixedHeight(42);
	rightWidget->setStyleSheet("QWidget { background: #222232; border-radius: 5px; }");
	QHBoxLayout *rightLayout = new QHBoxLayout(rightWidget);
	rightLayout->setContentsMargins(5, 0, 5, 0);
	rightLayout->setSpacing(0);

	// 横屏按钮
	m_landscapeBtn = new QPushButton("横屏", this);
	m_landscapeBtn->setFixedSize(56, 28);
	m_landscapeBtn->setCursor(Qt::PointingHandCursor);
	m_landscapeBtn->setCheckable(true);
	m_landscapeBtn->setChecked(true);
	connect(m_landscapeBtn, &QPushButton::clicked, this, [this]() {
		if (m_isLandscape) return;
		m_isLandscape = true;
		updateOrientationButtons();
		emit orientationChanged(true);
	});
	rightLayout->addWidget(m_landscapeBtn);

	// 竖屏按钮
	m_portraitBtn = new QPushButton("竖屏", this);
	m_portraitBtn->setFixedSize(56, 28);
	m_portraitBtn->setCursor(Qt::PointingHandCursor);
	m_portraitBtn->setCheckable(true);
	m_portraitBtn->setChecked(false);
	connect(m_portraitBtn, &QPushButton::clicked, this, [this]() {
		if (!m_isLandscape) return;
		m_isLandscape = false;
		updateOrientationButtons();
		emit orientationChanged(false);
	});
	rightLayout->addWidget(m_portraitBtn);

	updateOrientationButtons();

	rightLayout->addSpacing(8);

	// 分隔线
	QWidget *separator = new QWidget(this);
	separator->setFixedSize(1, 16);
	separator->setStyleSheet("background-color: rgba(71, 71, 103, 255);");
	rightLayout->addWidget(separator);

	rightLayout->addSpacing(8);

	// 设置按钮
	m_settingBtn = new QPushButton(this);
	m_settingBtn->setFixedSize(20, 20);
	m_settingBtn->setStyleSheet(BUTTON_QSS_STYLE("setting.svg", "setting_hover.svg", "setting_hover.svg"));
	m_settingBtn->setToolTip("设置");
	connect(m_settingBtn, &QPushButton::clicked, this, [this]() { emit settingsRequested(1); });
	rightLayout->addWidget(m_settingBtn);

	m_layout->addWidget(rightWidget);
}

void PreviewHeader::updateOrientationButtons()
{
	QString activeStyle =
		"QPushButton {"
		"    background-color: #454558;"
		"    color: #FFFFFF;"
		"    font-size: 13px;"
		"    font-weight: bold;"
		"    border: none;"
		"    border-radius: 4px;"
		"}";
	QString inactiveStyle =
		"QPushButton {"
		"    background-color: transparent;"
		"    color: #AAABB8;"
		"    font-size: 13px;"
		"    font-weight: medium;"
		"    border: none;"
		"    border-radius: 4px;"
		"}"
		"QPushButton:hover {"
		"    color: #FFFFFF;"
		"    background-color: rgba(69, 69, 88, 0.5);"
		"}";

	m_landscapeBtn->setChecked(m_isLandscape);
	m_portraitBtn->setChecked(!m_isLandscape);
	m_landscapeBtn->setStyleSheet(m_isLandscape ? activeStyle : inactiveStyle);
	m_portraitBtn->setStyleSheet(!m_isLandscape ? activeStyle : inactiveStyle);
}

void PreviewHeader::loadCurrentPlatformInfo()
{
	OBSBasic *main = OBSBasic::Get();
	config_t *config = main ? main->Config() : nullptr;
	if (!config)
		return;

	// 读取当前平台索引
	int curIdx = (int)config_get_int(config, "CometStream", "CurrentPlatform");
	if (curIdx < 0)
		curIdx = 0;

	// 读取平台名
	const char *platformsStr = config_get_string(config, "CometStream", "Platforms");
	QString platformName;
	if (platformsStr && *platformsStr) {
		QStringList platforms = QString::fromUtf8(platformsStr).split('|', Qt::SkipEmptyParts);
		if (curIdx < platforms.size())
			platformName = platforms[curIdx];
	}

	// 读取图标路径
	QString key = QString::number(curIdx) + "_Icon";
	const char *iconFile = config_get_string(config, "CometStream", QT_TO_UTF8(key));
	QString iconPath;
	if (iconFile && *iconFile) {
		QString iconStr = QString::fromUtf8(iconFile);
		iconPath = iconStr.startsWith(":/") ? iconStr : QString(":/images/%1").arg(iconStr);
	}

	setStreamPlatform(platformName, iconPath);

	// 根据当前分辨率判断横竖屏
	uint32_t baseCX = config_get_uint(config, "Video", "BaseCX");
	uint32_t baseCY = config_get_uint(config, "Video", "BaseCY");
	if (baseCX > 0 && baseCY > 0) {
		m_isLandscape = (baseCX >= baseCY);
		updateOrientationButtons();
	}
}

void PreviewHeader::setStreamPlatform(const QString &name, const QString &iconPath)
{
	Q_UNUSED(name);
	if (!iconPath.isEmpty()) {
		QIcon icon(iconPath);
		QPixmap pix = icon.pixmap(36, 24);
		if (!pix.isNull())
			m_platformIcon->setPixmap(pix);
	}
}

void PreviewHeader::setStreamStatus(bool streaming, const QString &statusText)
{
	if (streaming) {
		m_statusDot->setStyleSheet(
			"QLabel {"
			"    background-color: #00FF00;"
			"    border-radius: 4px;"
			"    border: none;"
			"}");
		m_statusLabel->setText(statusText.isEmpty() ? "直播中" : statusText);
		m_statusLabel->setStyleSheet("QLabel { color: #00FF00; font-size: 14px; background: transparent; border: none; }");
	} else {
		m_statusDot->setStyleSheet(
			"QLabel {"
			"    background-color: #FF3040;"
			"    border-radius: 4px;"
			"    border: none;"
			"}");
		m_statusLabel->setText(statusText.isEmpty() ? "未启用" : statusText);
		m_statusLabel->setStyleSheet("QLabel { color: #AAABB8; font-size: 14px; background: transparent; border: none; }");
	}
}
