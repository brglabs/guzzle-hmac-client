<?php

namespace BRG\GuzzleHmacClient;

use GuzzleHttp\Handler\CurlHandler;
use Psr\Http\Message\RequestInterface;

use Zend\Http\Exception\RuntimeException;

use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;

use RB\Sphinx\Hmac\HMAC;
use RB\Sphinx\Hmac\HMACSession;

class HMACHttpClient extends Client
{
    const HMAC_VERSION = 1;
    const HEADER_NAME = 'HMAC-Authentication';

    protected $httpClient;
    protected $requestHeaders;
    protected $assinaturaHmacLocal;

    /**
     *
     * @var HMAC
     */
    protected $hmac = null;

    /**
     * Contador de mensagens enviadas
     * @var int
     */
    protected $hmacContador = 0;

    /**
     * Indicar se sessão já foi iniciada
     * @var bool
     */
    protected $hmacSession = false;

    /**
     * Indicar se URI já foi autenticada
     * @var bool
     */
    protected $hmacSignedUri = false;
    protected $hmacSignedUriString = null;

    public function __construct(HMAC $hmac)
    {
        $this->hmac = $hmac;
        parent::__construct([]);
    }

    /**
    * Verificar assinatura da resposta do servidor (sem sessão)
    */
    protected function verify(Response $response)
    {
        if (!$response->hasHeader(self::HEADER_NAME)) {
            throw new RuntimeException('HMAC não está presente na resposta');
        }

        $headerResponse = $response->getHeader(self::HEADER_NAME);
        $resHmacPieces = explode(':', $headerResponse[0]);
        if (count($resHmacPieces) != 4) {
            throw new RuntimeException('HMAC da resposta é inválido (header incorreto)');
        }

        $resVersion    = $resHmacPieces[0];
        $resAppKeyId   = $resHmacPieces[1];
        $resNonce      = $resHmacPieces[2];
        $resAssinatura = $resHmacPieces[3];
        /**
         * Verificar versão do protocolo
         */
        if ($resVersion != self::HMAC_VERSION) {
            throw new RuntimeException('HMAC da resposta é inválido (versão incorreta)');
        }

        /**
         * Verificar assinatura
         */
        $this->hmac->validate($this->assinaturaHmacLocal, $resAssinatura, HMACSession::SESSION_MESSAGE);
    }

    protected function sign(Request $request)
    {
        if ($this->hmacContador > 0) {
            throw new RuntimeException('HMAC sem sessão só pode enviar uma mensagem');
        }

        /**
         * Dados a assinar (versão 1 do protocolo)
         */
        $this->assinaturaHmacLocal = "{$request->getMethod()}{$request->getUri()}";

        /**
         * Assinatura HMAC
         */
        $assinaturaHmac = $this->hmac->getHmac($this->assinaturaHmacLocal, HMACSession::SESSION_REQUEST);

        /**
         * Header de autenticação (protocolo versão 1)
         */
        $headerAuth = self::HMAC_VERSION          // versão do protocolo
            . ':' . $this->hmac->getKeyId()       // ID da chave/aplicação/cliente
            . ':' . $this->hmac->getNonceValue()  // nonce
            . ':' . $assinaturaHmac;              // HMAC Hash

        $this->setHeader('headers', self::HEADER_NAME, $headerAuth);
    }

    /**
     * @param $method
     * @param $uri
     */
    public function call(
        string $method,
        string $uri,
        array $headers = [],
        string $body = null,
        string $version = '1.1'
    )
    {
        if ($this->hmac === null) {
            throw new RuntimeException('HMAC é necessário para a requisição');
        }

        $this->prepareHeaders($headers);

        /** @var $request - Criando a solicitação */
        $request = new Request(
            $method,
            $uri,
            [],
            $body,
            $version
        );

        /** Assinar requisição */
        $this->sign($request);

        /**
         * Enviar requisição
         */
        $response = $this->send($request, $this->requestHeaders);

        /**
         * Verificar se servidor informou erro de HMAC
         */
        if ($response->getStatusCode() == 401) {
            $detalhes = '';
            try {
                $json = json_decode($response->getBody());
                if ($json === null) {
                    /**
                     * Erro 401 não gerado pelo HMAC no servidor
                     */
                    $detalhes = $response->getBody();
                } else {
                    if (!property_exists($json, 'detail')) {
                        /**
                         * JSON não foi gerado pelo HMAC Server
                         */
                        $detalhes = $response->getBody();
                    } else {
                        $detalhes = $json->detail;
                        /**
                         * Alertar da necessidade de início de sessão para comunicação com URI
                         */
                        if (strcmp($json->detail, 'HMAC Authentication required') == 0) {
                            if ($this->hmac instanceof HMACSession) {
                                $detalhes .= ' (sessão HMAC expirou)';
                            } else {
                                $detalhes .= ' (servidor requer HMAC com sessão)';
                            }
                        } elseif (strcmp($json->detail, '5 - Sessão HMAC não iniciada') == 0) {
                            if ($this->hmac instanceof HMACSession) {
                                $detalhes .= ' (sessão HMAC expirou)';
                            } else {
                                $detalhes .= ' (servidor requer HMAC com sessão)';
                            }
                        }
                        /**
                         * Detalhes adicionais enviados pelo servidor
                         */
                        if (property_exists($json, 'hmac'))
                            $detalhes .= ' [' . $json->hmac . ' v' . $json->version . ']';
                    }
                }
            } catch (Exception $e) {

            }
            throw new RuntimeException('Erro HMAC remoto: ' . $detalhes, 401);
        }

        /**
         * Verificar assinatura da resposta, se for resposta de sucesso (2xx)
         */
        if ($response->getStatusCode() >= 200 && $response->getStatusCode() <= 299) {
            $this->verify($response);
        }

        /**
         * Incrementar contador interno após validar resposta
         */
        $this->hmacContador++;

        return $response;
    }

    private function prepareHeaders(array $headers)
    {
        if (array_key_exists('headers', $headers)) {
            foreach ($headers['headers'] as $key => $value) {
                $this->setHeader('headers', $key, $value);
            }
        }

        if (array_key_exists('form_params', $headers)) {
            foreach ($headers['form_params'] as $key => $value) {
                $this->setHeader('form_params', $key, $value);
            }
        }
    }

    private function setHeader(string $headerType, string $key, string $value)
    {
        $this->requestHeaders[$headerType][$key] = $value;
    }
}