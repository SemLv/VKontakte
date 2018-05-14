<?php

namespace SocialiteProviders\VKontakte;

use Illuminate\Support\Arr;
use Laravel\Socialite\Two\ProviderInterface;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;

class Provider extends AbstractProvider implements ProviderInterface
{
    protected $fields = ['uid', 'email', 'first_name', 'last_name', 'screen_name', 'photo'];

    /**
     * Unique Provider Identifier.
     */
    const IDENTIFIER = 'VKONTAKTE';

    /**
     * {@inheritdoc}
     */
    protected $scopes = ['email'];

    /**
     * {@inheritdoc}
     */
    const API_VERSION = '5.74';

    protected $parameters = [
        'v' => self::API_VERSION,
    ];

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase(
            'https://oauth.vk.com/authorize', $state
        );
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl()
    {
        return 'https://oauth.vk.com/access_token';
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        $from_token = [];

        if(is_array($token)) {
            $from_token["email"] = $token["email"] ?? null;
            $token = $token["access_token"] ?? null;
        }

        $lang = $this->getConfig('lang');

        $response = $this->getHttpClient()->get(
            'https://api.vk.com/method/users.get?'.http_build_query([
                'access_token' => $token,
                'fields' => implode(',', $this->fields),
                'lang' => $lang ?: 'ru',
                'v' => self::API_VERSION,
            ])
        );
        $contents = $response->getBody()->getContents();
        $response = json_decode($contents, true);
        if (!is_array($response) || !isset($response['response'][0])) {
            throw new \RuntimeException(sprintf(
                'Invalid JSON response from VK: %s',
                $contents
            ));
        }

        $result = $response["response"][0];

        return array_merge($result, $from_token);
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        return (new User())->setRaw($user)->map([
            'id'       => Arr::get($user, 'id'),
            'nickname' => Arr::get($user, 'screen_name'),
            'name'     => trim(Arr::get($user, 'first_name').' '.Arr::get($user, 'last_name')),
            'email'    => Arr::get($user, 'email'),
            'avatar'   => Arr::get($user, 'photo'),
        ]);
    }

    protected function parseAccessToken($body) {
        return json_decode($body, true);
    }

    public function user() {
        if ($this->hasInvalidState()) {
            throw new \RuntimeException();
        }

        $user = $this->mapUserToObject($this->getUserByToken(
            $token = $this->getAccessTokenResponse($this->getCode())
        ));

        return $user->setToken(array_get($token, 'access_token'));
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenFields($code)
    {
        return array_merge(parent::getTokenFields($code), [
            'grant_type' => 'authorization_code',
        ]);
    }

    /**
     * Set the user fields to request from Vkontakte.
     *
     * @param array $fields
     *
     * @return $this
     */
    public function fields(array $fields)
    {
        $this->fields = $fields;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public static function additionalConfigKeys()
    {
        return ['lang'];
    }
}
