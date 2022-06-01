<?php
/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2019, TASoft Applications
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *  Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

namespace Skyline\Security\Controller;


use Skyline\Application\Controller\AbstractActionController;
use Skyline\Render\Info\RenderInfoInterface;
use Skyline\Router\Description\ActionDescriptionInterface;
use Skyline\Security\Exception\AuthorizationException;
use Skyline\Security\User\Provider\UserProviderInterface;
use Skyline\Security\User\UserInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

abstract class AbstractSecurityLiteActionController extends AbstractActionController
{
	const HTTP_AUTH_MODE_UNKNOWN = 0;
	const HTTP_AUTH_MODE_BASIC = 1;
	const HTTP_AUTH_MODE_DIGEST = 2;

	/** @var UserProviderInterface */
	protected $user_provider;
	/** @var Request */
	protected $access_request;
	/** @var Response */
	protected $access_response;

	private $authenticated;

	private $digest_opts;

	private $mode = self::HTTP_AUTH_MODE_UNKNOWN;

	public function getRealm(): string {
		return "Skyline CMS";
	}

	/**
	 * @return string
	 */
	public function getNonce(): string
	{
		return md5(date("Y-m-d G:i"));
	}

	/**
	 * @return string
	 */
	public function getOpaque(): string
	{
		return md5("skyline.cms.digest");
	}


	public function performAction(ActionDescriptionInterface $actionDescription, RenderInfoInterface $renderInfo)
	{
		$this->access_request = $this->get("request");
		$this->access_response = $this->get("response");

		$this->user_provider = $this->prepareUserProvider();
		parent::performAction($actionDescription, $renderInfo);
	}


	/**
	 * This method must prepare the user provider to support users.
	 */
	abstract protected function prepareUserProvider(): UserProviderInterface;

	/**
	 * @return int
	 */
	abstract protected function getDefaultAuthenticationMode(): int;

	/**
	 * @return int
	 */
	public function getMode(): int
	{
		return $this->mode;
	}


	/**
	 * @param Request $request
	 * @param $user
	 * @param $pass
	 * @return int
	 */
	protected function fetchIdentity(Request $request, &$user, &$pass): int
	{
		$auth = $request->headers->get("Authorization");
		if(stripos($auth, 'basic') === 0) {
			$auth = substr($auth, 6);
			$auth = explode(":", base64_decode($auth), 2);
			if(count($auth) != 2)
				return -1;
			$user = $auth[0];
			$pass = $auth[1];
			return $this->mode = self::HTTP_AUTH_MODE_BASIC;
		}
		if(stripos($auth, 'digest') === 0) {
			$data = (function ($digest) {
				$needed_parts = ['nonce'=>1, 'nc'=>1, 'cnonce'=>1, 'qop'=>1, 'username'=>1, 'uri'=>1, 'response'=>1, 'opaque' => 1];
				$data = [];
				preg_match_all('@(\w+)=(?:(?:")([^"]+)"|([^\s,$]+))@', $digest, $matches, PREG_SET_ORDER);
				foreach ($matches as $m) {
					$data[$m[1]] = $m[2] ? $m[2] : $m[3];
					unset($needed_parts[$m[1]]);
				}
				return $needed_parts ? false : $data;
			})($auth);

			if($data) {
				$user = $data['username'];
				$pass = $data["response"];
				unset($data["username"]);
				unset($data["response"]);
				$this->digest_opts = $data;
				return $this->mode = self::HTTP_AUTH_MODE_DIGEST;
			}
		}
		return $this->mode = self::HTTP_AUTH_MODE_UNKNOWN;
	}

	/**
	 * @param $user
	 * @param $pass
	 * @return UserInterface|null
	 */
	protected function authenticateIdentity($user, $pass): ?UserInterface
	{
		$user = $this->user_provider->loadUserWithToken( $user );

		if($this->getMode() == self::HTTP_AUTH_MODE_DIGEST) {
			$uri = $this->digest_opts["uri"] ?? $_SERVER["REQUEST_URI"];
			$method = strtoupper( $this->access_request->getMethod() );
			$A1 = $user->getCredentials();
			$A2 = md5("$method:$uri");

			$response = md5("{$A1}:{$this->digest_opts['nonce']}:{$this->digest_opts['nc']}:{$this->digest_opts['cnonce']}:{$this->digest_opts['qop']}:{$A2}");
			if(hash_equals($response, $pass)) {
				$user->eraseCredentials();
				return $this->authenticated = $user;
			}
		} elseif($this->getMode() == self::HTTP_AUTH_MODE_BASIC && hash_equals($user->getCredentials(), $pass)) {
			$user->eraseCredentials();
			return $this->authenticated = $user;
		}
		return NULL;
	}

	/**
	 * @return UserInterface|null
	 */
	protected function getUser(): ?UserInterface {
		if(NULL === $this->authenticated) {
			if($this->fetchIdentity($this->access_request, $u, $p)) {
				if($this->authenticateIdentity($u, $p))
					return $this->authenticated;
			}
			$this->authenticated = false;
		}
		return $this->authenticated ?: NULL;
	}

	/**
	 * @param null $modus
	 * @return UserInterface
	 */
	protected function requireUser($modus = NULL): UserInterface {
		if(!$_COOKIE['ikarus-logout'] && ($u = $this->getUser())) {
			define("IKARUS_USER", $this->getUser()->getUsername());
			return $this->getUser();
		}
		setcookie('ikarus-logout', 0);
		$this->challengeClient($modus);
		exit();
	}

	/**
	 * @param int $mode
	 */
	protected function challengeClient($mode = self::HTTP_AUTH_MODE_UNKNOWN) {
		if(!$mode)
			$mode = $this->getMode();

		switch ($mode) {
			case 1:
				$this->access_response->headers->set('WWW-Authenticate', sprintf('Basic realm="%s"', $this->getRealm()));
				break;
			case 2:
				$this->access_response->headers->set('WWW-Authenticate', sprintf('Digest realm="%s",qop="auth",nonce="%s",opaque="%s"', $this->getRealm(), $this->getNonce(), $this->getOpaque()));
				break;
		}

		$this->access_response->prepare($this->access_request);
		$this->access_response->setContent($this->getChallengeHTMLContents());
		$this->access_response->setStatusCode(401);
		$this->access_response->sendHeaders();
		$this->access_response->send();
		exit();
	}

	/**
	 * @return string
	 */
	protected function getChallengeHTMLContents(): string {
		return "<b>401 Unauthorized</b><br>Access denied to the requested scope.";
	}

	/**
	 * @param string $access
	 */
	protected function checkAccess(string $access) {
		$roles = $this->requireUser()->getRoles();

		foreach($roles as &$role)
			$role = $role->getRole();

		if(!(function() use ($access, $roles) {
			$access = preg_replace_callback("/\w+/i", function($ms) use ($roles) {
				return in_array($ms[0], $roles) ? 1 : 0;
			}, $access);
			if(!$access)
				return false;
			return eval("return (bool) $access;");
		})() ) {
			$e = new AuthorizationException("Unauthorized", 403);
			$e->setUser($this->getUser());
			throw $e;
		}
	}
}