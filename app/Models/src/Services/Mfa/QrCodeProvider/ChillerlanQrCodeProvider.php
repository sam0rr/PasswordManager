<?php
namespace Models\src\Services\Mfa\QrCodeProvider;

use chillerlan\QRCode\Output\QRGdImagePng;
use chillerlan\QRCode\{QRCode, QROptions};
use chillerlan\QRCode\Common\EccLevel;
use chillerlan\QRCode\Data\QRMatrix;
use RobThree\Auth\Providers\Qr\IQRCodeProvider;

final class ChillerlanQrCodeProvider implements IQRCodeProvider
{
    public function getQRCodeImage(string $qrText, int $size): string
    {
        $options = new QROptions([
            'outputType' => 'png',
            'outputInterface' => QRGdImagePng::class,
            'outputBase64' => false,

            'eccLevel' => EccLevel::H,

            'scale' => 6,

            'margin' => 2,

            'bgColor' => [255, 255, 255],

            'drawCircularModules' => true,
            'circleRadius' => 0.45,

            'addQuietzone' => true,
            'quietzoneSize' => 2,

            'moduleValues' => [
                QRMatrix::M_DATA_DARK => [74, 144, 226],

                QRMatrix::M_FINDER_DARK => [28, 56, 148],
                QRMatrix::M_FINDER_DOT => [28, 56, 148],

                QRMatrix::M_ALIGNMENT_DARK => [54, 124, 206],
                QRMatrix::M_TIMING_DARK => [84, 154, 236],

                QRMatrix::M_FORMAT_DARK => [74, 144, 226],
                QRMatrix::M_VERSION_DARK => [74, 144, 226],
                QRMatrix::M_DARKMODULE => [28, 56, 148],
            ],

            'drawLightModules' => false,

            'connectPaths' => true,
            'excludeFromConnect' => [
                QRMatrix::M_FINDER_DARK,
                QRMatrix::M_FINDER_DOT,
            ],
        ]);

        return new QRCode($options)->render($qrText);
    }

    public function getQRCodeImageMimeType(): string
    {
        return 'image/png';
    }

    public function getMimeType(): string
    {
        return $this->getQRCodeImageMimeType();
    }

}