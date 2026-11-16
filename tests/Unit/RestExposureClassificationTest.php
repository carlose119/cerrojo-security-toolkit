<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\RestExposureClassification;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use stdClass;

final class AlwaysThrows
{
    public function __invoke(): never
    {
        throw new RuntimeException('secret-invocation');
    }

    public static function staticThrow(): never
    {
        throw new RuntimeException('secret-invocation');
    }
}

final class RestExposureClassificationTest extends TestCase
{
    public function testAbsentClassifiesMissingOrNullCallbackWithHonestWording(): void
    {
        self::assertSame(RestExposureClassification::ABSENT, RestExposureClassification::classify(null));
        self::assertSame(
            RestExposureClassification::OPAQUE,
            RestExposureClassification::classify(['methods' => ['GET' => true]]),
        );

        $label = RestExposureClassification::label(RestExposureClassification::ABSENT);
        self::assertStringContainsStringIgnoringCase('no permission callback registered', $label);
        self::assertStringNotContainsStringIgnoringCase('is public', $label);
        self::assertStringNotContainsStringIgnoringCase('safe', $label);
    }

    public function testEmptyRegisteredValuesAreAbsentBecauseWordPressSkipsTheCheck(): void
    {
        // WordPress dispatch runs the callback only when `! empty( $permission_callback )`,
        // so a registered false denies nothing: the check is skipped entirely.
        self::assertSame(RestExposureClassification::ABSENT, RestExposureClassification::classify(false));
        self::assertSame(RestExposureClassification::ABSENT, RestExposureClassification::classify(''));
        self::assertSame(RestExposureClassification::ABSENT, RestExposureClassification::classify(0));
        self::assertSame(RestExposureClassification::ABSENT, RestExposureClassification::classify('0'));
        self::assertSame(RestExposureClassification::ABSENT, RestExposureClassification::classify([]));

        // Non-empty values never collapse into absent.
        self::assertSame(RestExposureClassification::OPAQUE, RestExposureClassification::classify(true));
        self::assertSame(RestExposureClassification::OPAQUE, RestExposureClassification::classify('strlen'));

        $label = RestExposureClassification::label(RestExposureClassification::ABSENT);
        self::assertStringContainsStringIgnoringCase('empty', $label);
        self::assertStringContainsStringIgnoringCase('no check', $label);
    }

    public function testPublicAndDeniedClassifyTheTwoWordPressShorthands(): void
    {
        self::assertSame(RestExposureClassification::PUBLIC, RestExposureClassification::classify('__return_true'));
        self::assertSame(RestExposureClassification::DENIED, RestExposureClassification::classify('__return_false'));
        self::assertSame(RestExposureClassification::PUBLIC, RestExposureClassification::classify('__RETURN_TRUE'));
    }

    public function testEveryOtherCallableFormIsOpaqueWithoutThrowing(): void
    {
        $object = new stdClass();
        $invokable = new AlwaysThrows();

        self::assertSame(RestExposureClassification::OPAQUE, RestExposureClassification::classify(static fn (): bool => true));
        self::assertSame(RestExposureClassification::OPAQUE, RestExposureClassification::classify([$object, 'someMethod']));
        self::assertSame(RestExposureClassification::OPAQUE, RestExposureClassification::classify([stdClass::class, 'someStaticMethod']));
        self::assertSame(RestExposureClassification::OPAQUE, RestExposureClassification::classify('strlen'));
        self::assertSame(RestExposureClassification::OPAQUE, RestExposureClassification::classify($invokable));
        self::assertSame(RestExposureClassification::OPAQUE, RestExposureClassification::classify([stdClass::class, 'parent']));
    }

    public function testUnclassifiableJunkDegradesToOpaqueAndNeverThrows(): void
    {
        self::assertSame(RestExposureClassification::OPAQUE, RestExposureClassification::classify('secret-permission'));
        self::assertSame(RestExposureClassification::OPAQUE, RestExposureClassification::classify(42));
        self::assertSame(RestExposureClassification::OPAQUE, RestExposureClassification::classify(true));
        self::assertSame(RestExposureClassification::OPAQUE, RestExposureClassification::classify(['wrong-shape']));
        self::assertSame(RestExposureClassification::OPAQUE, RestExposureClassification::classify([1, 2, 3]));
        self::assertSame(RestExposureClassification::OPAQUE, RestExposureClassification::classify(1.5));
    }

    public function testClassificationNeverInvokesTheCallbackItExamines(): void
    {
        $calls = 0;
        $counting = static function () use (&$calls): bool {
            ++$calls;

            return true;
        };
        $handlers = [
            ['methods' => ['GET' => true], 'permission_callback' => null],
            ['methods' => ['GET' => true]],
            ['methods' => ['GET' => true], 'permission_callback' => '__return_true'],
            ['methods' => ['GET' => true], 'permission_callback' => '__return_false'],
            ['methods' => ['GET' => true], 'permission_callback' => $counting],
            ['methods' => ['GET' => true], 'permission_callback' => [$counting, 'bar']],
            ['methods' => ['GET' => true], 'permission_callback' => new AlwaysThrows()],
            ['methods' => ['GET' => true], 'permission_callback' => [AlwaysThrows::class, 'staticThrow']],
            ['methods' => ['GET' => true], 'permission_callback' => 'secret-permission'],
            ['methods' => ['GET' => true], 'permission_callback' => 42],
        ];

        $classes = [];
        foreach ($handlers as $handler) {
            $classes[] = RestExposureClassification::classify($handler['permission_callback'] ?? null);
        }

        self::assertSame([
            RestExposureClassification::ABSENT,
            RestExposureClassification::ABSENT,
            RestExposureClassification::PUBLIC,
            RestExposureClassification::DENIED,
            RestExposureClassification::OPAQUE,
            RestExposureClassification::OPAQUE,
            RestExposureClassification::OPAQUE,
            RestExposureClassification::OPAQUE,
            RestExposureClassification::OPAQUE,
            RestExposureClassification::OPAQUE,
        ], $classes);
        self::assertSame(0, $calls, 'The counting callback must never be invoked by classification.');
    }

    public function testOpaqueLabelIsHonestAboutUnknownAuthorization(): void
    {
        $label = RestExposureClassification::label(RestExposureClassification::OPAQUE);
        self::assertStringContainsStringIgnoringCase('authorization', $label);
        self::assertStringContainsStringIgnoringCase('not invoked', $label);
        self::assertStringNotContainsStringIgnoringCase('is public', $label);
        self::assertStringNotContainsStringIgnoringCase('is authorised', $label);
        self::assertStringNotContainsStringIgnoringCase('is authorized', $label);
    }

    public function testPublicAndDeniedLabelsStayStructural(): void
    {
        $publicLabel = RestExposureClassification::label(RestExposureClassification::PUBLIC);
        self::assertStringContainsString('__return_true', $publicLabel);
        self::assertStringNotContainsStringIgnoringCase('is public', $publicLabel);

        $deniedLabel = RestExposureClassification::label(RestExposureClassification::DENIED);
        self::assertStringContainsString('__return_false', $deniedLabel);
        self::assertStringNotContainsStringIgnoringCase('is authorised', $deniedLabel);
        self::assertStringNotContainsStringIgnoringCase('is authorized', $deniedLabel);
    }

    public function testUnknownClassLabelDegradesWithoutThrowing(): void
    {
        self::assertSame(RestExposureClassification::label(RestExposureClassification::OPAQUE), RestExposureClassification::label('nonsense'));
    }

    public function testClassificationSourceContainsNoInvocationPrimitives(): void
    {
        $source = (string) file_get_contents(dirname(__DIR__, 2) . '/src/RestExposureClassification.php');

        self::assertStringNotContainsString('call_user_func', $source);
        self::assertStringNotContainsString('is_callable', $source);
        self::assertStringNotContainsString('->invoke', $source);
    }
}
