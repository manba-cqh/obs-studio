#include "VideoConfigWt.hpp"
#include <widgets/OBSBasic.hpp>
#include <QScrollArea>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QLabel>
#include <QGroupBox>
#include <QScreen>
#include <QGuiApplication>
#include <QLineEdit>
#include <QFrame>
#include <util/config-file.h>
#include <util/base.h>
#include <algorithm>
#include <cmath>
#include <obs.h>

#include "tools.hpp"

static QString ResString(uint32_t cx, uint32_t cy)
{
	return QString("%1*%2").arg(cx).arg(cy);
}

static std::tuple<int, int> aspect_ratio(uint32_t cx, uint32_t cy)
{
	if (cy == 0)
		return std::make_tuple(16, 9);
	
	uint32_t gcd_val = cx;
	uint32_t b = cy;
	
	// 计算最大公约数
	while (b != 0) {
		uint32_t temp = b;
		b = gcd_val % b;
		gcd_val = temp;
	}
	
	int common = gcd_val;
	int newCX = cx / common;
	int newCY = cy / common;
	
	// 特殊处理 8:5 的情况，转换为 16:10
	if (newCX == 8 && newCY == 5) {
		newCX = 16;
		newCY = 10;
	}
	
	return std::make_tuple(newCX, newCY);
}

VideoConfigWt::VideoConfigWt(QWidget *parent)
	: BaseConfigWt(parent)
	, m_config(nullptr)
{
	OBSBasic *main = OBSBasic::Get();
	if (main) {
		m_config = main->Config();
	}
	
	initUI();
	loadVideoSettings();
}

VideoConfigWt::~VideoConfigWt()
{
}

void VideoConfigWt::initUI()
{
	// 创建滚动区域
	m_scrollArea = new QScrollArea(this);
	m_scrollArea->setWidgetResizable(true);
	m_scrollArea->setFrameShape(QFrame::NoFrame);
	m_scrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
	
	// 创建内容容器
	m_contentWidget = new QWidget();
	m_contentLayout = new QVBoxLayout(m_contentWidget);
	m_contentLayout->setContentsMargins(20, 20, 20, 20);
	m_contentLayout->setSpacing(20);
	
	setupVideoSettings();
	
	m_contentLayout->addStretch();
	
	m_scrollArea->setWidget(m_contentWidget);
	
	QVBoxLayout *mainLayout = new QVBoxLayout(this);
	mainLayout->setContentsMargins(0, 0, 0, 0);
	mainLayout->addWidget(m_scrollArea);
}

void VideoConfigWt::setupVideoSettings()
{
	QFormLayout *formLayout = new QFormLayout();
	formLayout->setSpacing(15);
	formLayout->setLabelAlignment(Qt::AlignRight);
	
	// 基础(画布)分辨率
	QHBoxLayout *baseResLayout = new QHBoxLayout();
	m_baseResolutionCombo = new CommonComboBox();
	m_baseResolutionCombo->setEditable(true);
	m_baseAspectRatioLabel = new QLabel("长宽比 16:9");
	m_baseAspectRatioLabel->setMinimumWidth(100);
	baseResLayout->addWidget(m_baseResolutionCombo);
	baseResLayout->addWidget(m_baseAspectRatioLabel);
	formLayout->addRow("基础(画布)分辨率:", baseResLayout);
	connect(m_baseResolutionCombo, &QComboBox::currentTextChanged,
		this, &VideoConfigWt::onBaseResolutionChanged);
	connect(m_baseResolutionCombo->lineEdit(), &QLineEdit::editingFinished,
		this, &VideoConfigWt::onBaseResolutionChanged);
	
	// 输出(画布)分辨率
	QHBoxLayout *outputResLayout = new QHBoxLayout();
	m_outputResolutionCombo = new CommonComboBox();
	m_outputResolutionCombo->setEditable(true);
	m_outputAspectRatioLabel = new QLabel("长宽比 16:9");
	m_outputAspectRatioLabel->setMinimumWidth(100);
	outputResLayout->addWidget(m_outputResolutionCombo);
	outputResLayout->addWidget(m_outputAspectRatioLabel);
	formLayout->addRow("输出(画布)分辨率:", outputResLayout);
	connect(m_outputResolutionCombo, &QComboBox::currentTextChanged,
		this, &VideoConfigWt::onOutputResolutionChanged);
	connect(m_outputResolutionCombo->lineEdit(), &QLineEdit::editingFinished,
		this, &VideoConfigWt::onOutputResolutionChanged);
	
	// 缩小算法
	m_downscaleFilterCombo = new CommonComboBox();
	m_downscaleFilterCombo->addItem("双线性(快速缩放, 32个样本)", "bilinear");
	m_downscaleFilterCombo->addItem("区域(平滑缩放)", "area");
	m_downscaleFilterCombo->addItem("双三次插值(平滑缩放, 32个样本)", "bicubic");
	m_downscaleFilterCombo->addItem("Lanczos插值(锐化缩放, 36个样本)", "lanczos");
	formLayout->addRow("缩小算法:", m_downscaleFilterCombo);
	connect(m_downscaleFilterCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &VideoConfigWt::onDownscaleFilterChanged);
	
	// 常用帧率
	m_fpsCombo = new CommonComboBox();
	m_fpsCombo->addItem("10", "10");
	m_fpsCombo->addItem("20", "20");
	m_fpsCombo->addItem("24 NTSC", "23.976");
	m_fpsCombo->addItem("25 PAL", "25");
	m_fpsCombo->addItem("29.97 NTSC", "29.97");
	m_fpsCombo->addItem("30", "30");
	m_fpsCombo->addItem("48", "48");
	m_fpsCombo->addItem("50 PAL", "50");
	m_fpsCombo->addItem("59.94 NTSC", "59.94");
	m_fpsCombo->addItem("60", "60");
	m_fpsCombo->addItem("120", "120");
	formLayout->addRow("常用帧率:", m_fpsCombo);
	connect(m_fpsCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &VideoConfigWt::onFPSChanged);
	
	setFormLayoutLabelWidth(formLayout, 64);
	
	m_contentLayout->addLayout(formLayout);
}

void VideoConfigWt::loadVideoSettings()
{
	if (!m_config) {
		return;
	}
	
	// 加载分辨率列表
	m_baseResolutionCombo->clear();
	m_outputResolutionCombo->clear();
	
	// 添加屏幕分辨率
	for (QScreen *screen : QGuiApplication::screens()) {
		QSize as = screen->size();
		uint32_t as_width = as.width();
		uint32_t as_height = as.height();
		
		// 计算物理屏幕分辨率（考虑 HiDPI）
		as_width = round(as_width * screen->devicePixelRatio());
		as_height = round(as_height * screen->devicePixelRatio());
		
		QString res = ResString(as_width, as_height);
		if (m_baseResolutionCombo->findText(res) == -1) {
			m_baseResolutionCombo->addItem(res);
		}
		if (m_outputResolutionCombo->findText(res) == -1) {
			m_outputResolutionCombo->addItem(res);
		}
	}
	
	// 添加常用分辨率（横屏和竖屏）
	QStringList commonRes = {
		// 横屏分辨率
		"1920*1080", "1280*720", "2560*1440", "3840*2160",
		// 竖屏分辨率
		"1080*1920", "720*1280", "1440*2560", "2160*3840"
	};
	for (const QString &res : commonRes) {
		if (m_baseResolutionCombo->findText(res) == -1) {
			m_baseResolutionCombo->addItem(res);
		}
		if (m_outputResolutionCombo->findText(res) == -1) {
			m_outputResolutionCombo->addItem(res);
		}
	}
	
	// 加载当前分辨率
	uint32_t baseCX = config_get_uint(m_config, "Video", "BaseCX");
	uint32_t baseCY = config_get_uint(m_config, "Video", "BaseCY");
	uint32_t outputCX = config_get_uint(m_config, "Video", "OutputCX");
	uint32_t outputCY = config_get_uint(m_config, "Video", "OutputCY");
	
	QString baseRes = ResString(baseCX, baseCY);
	QString outputRes = ResString(outputCX, outputCY);
	
	// 同时阻止 QComboBox 和 QLineEdit 的信号
	m_baseResolutionCombo->blockSignals(true);
	m_baseResolutionCombo->lineEdit()->blockSignals(true);
	m_baseResolutionCombo->lineEdit()->setText(baseRes);
	m_baseResolutionCombo->lineEdit()->blockSignals(false);
	m_baseResolutionCombo->blockSignals(false);
	
	m_outputResolutionCombo->blockSignals(true);
	m_outputResolutionCombo->lineEdit()->blockSignals(true);
	m_outputResolutionCombo->lineEdit()->setText(outputRes);
	m_outputResolutionCombo->lineEdit()->blockSignals(false);
	m_outputResolutionCombo->blockSignals(false);
	
	updateAspectRatioLabels();
	
	// 加载缩小算法
	const char *scaleType = config_get_string(m_config, "Video", "ScaleType");
	if (!scaleType || strlen(scaleType) == 0) {
		scaleType = "lanczos";
	}
	
	for (int i = 0; i < m_downscaleFilterCombo->count(); i++) {
		if (m_downscaleFilterCombo->itemData(i).toString() == scaleType) {
			m_downscaleFilterCombo->blockSignals(true);
			m_downscaleFilterCombo->setCurrentIndex(i);
			m_downscaleFilterCombo->blockSignals(false);
			break;
		}
	}
	
	updateDownscaleFilter();
	
	// 加载帧率
	const char *fpsCommon = config_get_string(m_config, "Video", "FPSCommon");
	if (!fpsCommon || strlen(fpsCommon) == 0) {
		fpsCommon = "60";
	}
	
	int fpsIdx = m_fpsCombo->findText(fpsCommon);
	if (fpsIdx == -1) {
		// 如果没有找到，尝试查找最接近的
		fpsIdx = m_fpsCombo->findData(fpsCommon);
		if (fpsIdx == -1) {
			fpsIdx = 9; // 默认 60
		}
	}
	
	m_fpsCombo->blockSignals(true);
	m_fpsCombo->setCurrentIndex(fpsIdx);
	m_fpsCombo->blockSignals(false);
}

void VideoConfigWt::saveVideoSettings()
{
	if (!m_config) {
		return;
	}
	
	// 保存分辨率在各自的槽函数中处理
	// 保存缩小算法在 onDownscaleFilterChanged 中处理
	// 保存帧率在 onFPSChanged 中处理
}

QString VideoConfigWt::formatResolution(uint32_t width, uint32_t height)
{
	return ResString(width, height);
}

QString VideoConfigWt::calculateAspectRatio(uint32_t width, uint32_t height)
{
	auto aspect = aspect_ratio(width, height);
	return QString("长宽比 %1:%2").arg(std::get<0>(aspect)).arg(std::get<1>(aspect));
}

void VideoConfigWt::updateAspectRatioLabels()
{
	if (!m_config) {
		return;
	}
	
	uint32_t baseCX = config_get_uint(m_config, "Video", "BaseCX");
	uint32_t baseCY = config_get_uint(m_config, "Video", "BaseCY");
	uint32_t outputCX = config_get_uint(m_config, "Video", "OutputCX");
	uint32_t outputCY = config_get_uint(m_config, "Video", "OutputCY");
	
	m_baseAspectRatioLabel->setText(calculateAspectRatio(baseCX, baseCY));
	m_outputAspectRatioLabel->setText(calculateAspectRatio(outputCX, outputCY));
}

void VideoConfigWt::updateDownscaleFilter()
{
	if (!m_config) {
		return;
	}
	
	uint32_t baseCX = config_get_uint(m_config, "Video", "BaseCX");
	uint32_t baseCY = config_get_uint(m_config, "Video", "BaseCY");
	uint32_t outputCX = config_get_uint(m_config, "Video", "OutputCX");
	uint32_t outputCY = config_get_uint(m_config, "Video", "OutputCY");
	
	// 如果基础分辨率和输出分辨率相同，禁用缩小算法
	if (baseCX == outputCX && baseCY == outputCY) {
		m_downscaleFilterCombo->setEnabled(false);
	} else {
		m_downscaleFilterCombo->setEnabled(true);
	}
}

static bool ParseResolution(const QString &text, uint32_t &cx, uint32_t &cy)
{
	QStringList parts = text.split('*');
	if (parts.size() != 2) {
		return false;
	}
	
	bool ok1, ok2;
	cx = parts[0].toUInt(&ok1);
	cy = parts[1].toUInt(&ok2);
	
	return ok1 && ok2 && cx >= 32 && cy >= 32 && cx <= 32768 && cy <= 32768;
}

void VideoConfigWt::onBaseResolutionChanged()
{
	if (!m_config) {
		return;
	}
	
	QString text = m_baseResolutionCombo->currentText();
	uint32_t cx, cy;
	
	if (!ParseResolution(text, cx, cy)) {
		// 解析失败，恢复原值
		uint32_t baseCX = config_get_uint(m_config, "Video", "BaseCX");
		uint32_t baseCY = config_get_uint(m_config, "Video", "BaseCY");
		m_baseResolutionCombo->blockSignals(true);
		m_baseResolutionCombo->lineEdit()->blockSignals(true);
		m_baseResolutionCombo->lineEdit()->setText(ResString(baseCX, baseCY));
		m_baseResolutionCombo->lineEdit()->blockSignals(false);
		m_baseResolutionCombo->blockSignals(false);
		return;
	}
	
	// 检查值是否真的改变了
	uint32_t currentBaseCX = config_get_uint(m_config, "Video", "BaseCX");
	uint32_t currentBaseCY = config_get_uint(m_config, "Video", "BaseCY");
	if (currentBaseCX == cx && currentBaseCY == cy) {
		// 值没有改变，不需要保存和重置
		return;
	}
	
	// 保存分辨率
	config_set_uint(m_config, "Video", "BaseCX", cx);
	config_set_uint(m_config, "Video", "BaseCY", cy);
	
	// 如果输出分辨率未设置或无效，设置为与基础分辨率相同
	uint32_t outputCX = config_get_uint(m_config, "Video", "OutputCX");
	uint32_t outputCY = config_get_uint(m_config, "Video", "OutputCY");
	if (outputCX < 32 || outputCY < 32) {
		config_set_uint(m_config, "Video", "OutputCX", cx);
		config_set_uint(m_config, "Video", "OutputCY", cy);
		m_outputResolutionCombo->blockSignals(true);
		m_outputResolutionCombo->lineEdit()->blockSignals(true);
		m_outputResolutionCombo->lineEdit()->setText(ResString(cx, cy));
		m_outputResolutionCombo->lineEdit()->blockSignals(false);
		m_outputResolutionCombo->blockSignals(false);
	}
	
	config_save(m_config);
	
	// 更新长宽比标签
	updateAspectRatioLabels();
	updateDownscaleFilter();
	
	// 重置视频（如果视频未激活）
	OBSBasic *main = OBSBasic::Get();
	if (main && !obs_video_active()) {
		int ret = main->ResetVideo();
		if (ret != OBS_VIDEO_SUCCESS && ret != OBS_VIDEO_CURRENTLY_ACTIVE) {
			blog(LOG_WARNING, "Failed to reset video: %d", ret);
		}
	}
}

void VideoConfigWt::onOutputResolutionChanged()
{
	if (!m_config) {
		return;
	}
	
	QString text = m_outputResolutionCombo->currentText();
	uint32_t cx, cy;
	
	if (!ParseResolution(text, cx, cy)) {
		// 解析失败，恢复原值
		uint32_t outputCX = config_get_uint(m_config, "Video", "OutputCX");
		uint32_t outputCY = config_get_uint(m_config, "Video", "OutputCY");
		m_outputResolutionCombo->blockSignals(true);
		m_outputResolutionCombo->lineEdit()->blockSignals(true);
		m_outputResolutionCombo->lineEdit()->setText(ResString(outputCX, outputCY));
		m_outputResolutionCombo->lineEdit()->blockSignals(false);
		m_outputResolutionCombo->blockSignals(false);
		return;
	}
	
	// 检查值是否真的改变了
	uint32_t currentOutputCX = config_get_uint(m_config, "Video", "OutputCX");
	uint32_t currentOutputCY = config_get_uint(m_config, "Video", "OutputCY");
	if (currentOutputCX == cx && currentOutputCY == cy) {
		// 值没有改变，不需要保存和重置
		return;
	}
	
	// 保存分辨率
	config_set_uint(m_config, "Video", "OutputCX", cx);
	config_set_uint(m_config, "Video", "OutputCY", cy);
	
	config_save(m_config);
	
	// 更新长宽比标签
	updateAspectRatioLabels();
	updateDownscaleFilter();
	
	// 重置视频（如果视频未激活）
	OBSBasic *main = OBSBasic::Get();
	if (main && !obs_video_active()) {
		int ret = main->ResetVideo();
		if (ret != OBS_VIDEO_SUCCESS && ret != OBS_VIDEO_CURRENTLY_ACTIVE) {
			blog(LOG_WARNING, "Failed to reset video: %d", ret);
		}
	}
}

void VideoConfigWt::onDownscaleFilterChanged(int index)
{
	if (index < 0 || !m_config) {
		return;
	}
	
	QString scaleType = m_downscaleFilterCombo->itemData(index).toString();
	config_set_string(m_config, "Video", "ScaleType", QT_TO_UTF8(scaleType));
	config_save(m_config);
	
	// 重置视频（如果视频未激活）
	OBSBasic *main = OBSBasic::Get();
	if (main && !obs_video_active()) {
		int ret = main->ResetVideo();
		if (ret != OBS_VIDEO_SUCCESS && ret != OBS_VIDEO_CURRENTLY_ACTIVE) {
			blog(LOG_WARNING, "Failed to reset video: %d", ret);
		}
	}
}

void VideoConfigWt::onFPSChanged(int index)
{
	if (index < 0 || !m_config) {
		return;
	}
	
	QString fpsValue = m_fpsCombo->itemData(index).toString();
	config_set_string(m_config, "Video", "FPSCommon", QT_TO_UTF8(fpsValue));
	config_save(m_config);
	
	// 重置视频（如果视频未激活）
	OBSBasic *main = OBSBasic::Get();
	if (main && !obs_video_active()) {
		int ret = main->ResetVideo();
		if (ret != OBS_VIDEO_SUCCESS && ret != OBS_VIDEO_CURRENTLY_ACTIVE) {
			blog(LOG_WARNING, "Failed to reset video: %d", ret);
		}
	}
}

