#
# Cookbook Name:: openvpn
# OpenVPN knife plugin
#
# Copyright 2013, LLC Express 42
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

module OpenvpnPlugin
  class Openvpn < Chef::Knife
    def run
      ui.info 'knife openvpn (user|server) action ARGS OPTS'
    end

    deps do
      require 'chef/encrypted_data_bag_item'
      require 'json'
      require 'openssl'
    end

    def check_databag_secret
      databag_secret_file = File.join(Dir.pwd, '.chef/encrypted_data_bag_secret')
      unless File.exist? databag_secret_file
        fail_with "Can't find encrypted databag secret file at #{databag_secret_file}."
      end
    end

    def check_existing_databag(server_name, fail_if_exists = false)
      databag_directory = File.join(Dir.pwd, "data_bags/openvpn-#{server_name}")
      if File.directory? databag_directory
        if fail_if_exists # databag exists and we want to create new
          fail_with "Data bag directory #{databag_directory} already exists."
        end
      else
        unless fail_if_exists # no such databag, but we want to use it
          fail_with "Data bag #{databag_directory} not exists."
        end
      end
    end

    def fail_with(error_message)
      ui.error "Error: #{error_message}"
      exit 1
    end

    def make_name(cn, cert_config)
      name = OpenSSL::X509::Name.new
      name.add_entry 'CN', cn
      %w(C L O OU ST mail).each { |entry| name.add_entry(entry, cert_config[entry]) }
      name
    end

    def load_databag_secret
      databag_secret_file = File.join(Dir.pwd, '.chef/encrypted_data_bag_secret')
      secret = Chef::EncryptedDataBagItem.load_secret(databag_secret_file)
      secret
    end

    def get_extensions_factory(subject_cert, issuer_cert)
      factory = OpenSSL::X509::ExtensionFactory.new
      factory.subject_certificate = subject_cert
      factory.issuer_certificate = issuer_cert
      factory
    end

    def add_ca_extensions(ca_cert)
      ef = get_extensions_factory ca_cert, ca_cert
      ca_cert.add_extension(ef.create_extension('basicConstraints', 'CA:TRUE', true))
      ca_cert.add_extension(ef.create_extension('keyUsage', 'keyCertSign, cRLSign', true))
      ca_cert.add_extension(ef.create_extension('subjectKeyIdentifier', 'hash', false))
      ca_cert.add_extension(ef.create_extension('authorityKeyIdentifier', 'keyid:always', false))
    end

    def add_endentity_extensions(entity_cert, ca_cert, is_user = false)
      ef = get_extensions_factory entity_cert, ca_cert
      entity_cert.add_extension(ef.create_extension('keyUsage', 'digitalSignature', true))
      entity_cert.add_extension(ef.create_extension('subjectKeyIdentifier', 'hash', false))
      entity_cert.add_extension(ef.create_extension('nsCertType', 'server')) unless is_user
    end

    def generate_cert_and_key(subject, cert_config, selfsigned = false, ca_cert = nil, ca_key = nil, is_user = false)
      key = OpenSSL::PKey::RSA.generate(cert_config['rsa_keysize'])
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = Time.now.to_i
      cert.public_key = key.public_key

      cert.not_after = Time.now + (cert_config['years_to_expire'] * 365 * 24 * 60 * 60)
      cert.not_before = Time.now - (24 * 60 * 60)

      if selfsigned
        cert.subject = subject
        cert.issuer = subject
        add_ca_extensions(cert)
        cert.sign(key, OpenSSL::Digest::SHA256.new)
      else
        if ca_cert.nil? || ca_key.nil?
          fail_with "CA key or cert isn't specified"
        end
        cert.subject = subject
        cert.issuer = ca_cert.subject
        add_endentity_extensions(cert, ca_cert, is_user)
        cert.sign(ca_key, OpenSSL::Digest::SHA256.new)
      end

      if is_user
        require 'highline/import'
        passphrase = ask('Enter a passphrase [blank for passphraseless]: ') { |q| q.echo = false }
        unless passphrase == ''
          cipher = OpenSSL::Cipher.new('AES-256-CBC')
          key = key.export(cipher, passphrase)
        end
      end

      [cert, key]
    end

    def issue_crl(revoke_info, serial, lastup, nextup, extensions,
                 issuer, issuer_key, digest)
      crl = OpenSSL::X509::CRL.new
      crl.issuer = issuer.subject
      crl.version = 1
      crl.last_update = lastup
      crl.next_update = nextup
      revoke_info.each do|rserial, time, reason_code|
        revoked = OpenSSL::X509::Revoked.new
        revoked.serial = rserial
        revoked.time = time
        enum = OpenSSL::ASN1::Enumerated(reason_code)
        ext = OpenSSL::X509::Extension.new('CRLReason', enum)
        revoked.add_extension(ext)
        crl.add_revoked(revoked)
      end
      ef = OpenSSL::X509::ExtensionFactory.new
      ef.issuer_certificate = issuer
      ef.crl = crl
      crlnum = OpenSSL::ASN1::Integer(serial)
      crl.add_extension(OpenSSL::X509::Extension.new('crlNumber', crlnum))
      extensions.each do|oid, value, critical|
        crl.add_extension(ef.create_extension(oid, value, critical))
      end
      crl.sign(issuer_key, digest)
      crl
    end

    def load_cert_and_key(cert_str, key_str)
      cert = OpenSSL::X509::Certificate.new cert_str
      key = OpenSSL::PKey::RSA.new key_str
      [cert, key]
    end

    def get_databag_path(server_name)
      directory_path = File.join(Dir.pwd, "data_bags/openvpn-#{server_name}")
      directory_path
    end

    def get_databag_name(server_name)
      databag_name = "openvpn-#{server_name}"
      databag_name
    end

    def save_databag_item(id, server_name, item_hash)
      databag_path = get_databag_path server_name
      item_hash['id'] = id
      item_path = File.join(databag_path, "#{id}.json")
      secret = load_databag_secret
      encrypted_data = Chef::EncryptedDataBagItem.encrypt_data_bag_item(item_hash, secret)
      if File.exist? item_path
        fail_with "#{item_path} already exists"
      else
        File.write item_path, JSON.pretty_generate(encrypted_data)
      end
    end

    def load_databag_item(databag_name, item_id)
      secret = load_databag_secret
      # puts "Loading [#{databag_name}:#{item_id}]"
      item = Chef::EncryptedDataBagItem.load(databag_name, item_id, secret)
      item
    end
  end

  class OpenvpnServerCreate < Openvpn
    banner 'knife openvpn server create NAME (options)'
    deps do
      require 'readline'
    end

    def run
      check_arguments
      vpn_server_name = name_args.first
      check_existing_databag vpn_server_name, true
      check_databag_secret
      create_new_server vpn_server_name
    end

    def create_new_server(vpn_server_name)
      now = Time.at(Time.now.to_i)
      cert_config = ask_for_cert_config
      ca_subject = make_name 'CA', cert_config
      ca_cert, ca_key = generate_cert_and_key ca_subject, cert_config, true
      server_subject = make_name vpn_server_name, cert_config
      server_cert, server_key = generate_cert_and_key server_subject, cert_config, false, ca_cert, ca_key
      dh_params = make_dh_params cert_config
      crl = issue_crl([], 1, now, now + 3600, [], ca_cert, ca_key, OpenSSL::Digest::SHA256.new)
      databag_path = get_databag_path vpn_server_name
      ui.info "Creating data bag directory at #{databag_path}"
      create_databag_dir vpn_server_name
      save_databag_item('openvpn-config', vpn_server_name, cert_config)
      save_databag_item('openvpn-ca', vpn_server_name, 'cert' => ca_cert.to_pem, 'key' => ca_key.to_pem)
      save_databag_item('openvpn-crl', vpn_server_name, 'crl' => crl.to_pem, 'revoke_info' => [])

      save_databag_item('openvpn-server', vpn_server_name, 'cert' => server_cert.to_pem, 'key' => server_key.to_pem)
      save_databag_item('openvpn-dh', vpn_server_name, 'dh' => dh_params.to_pem)
    end

    def check_arguments
      fail_with 'Specify NAME of new openvpn server!' unless name_args.size == 1
    end

    def create_databag_dir(server_name)
      databag_path = get_databag_path server_name
      Dir.mkdir(databag_path, 0755)
      databag_path
    end

    def read_with_prompt_and_default(prompt, default)
      answer = Readline.readline("#{prompt} [#{default}]: ").strip
      if answer.empty?
        default
      else
        answer
      end
    end

    def make_dh_params(cert_config)
      keysize = cert_config['dh_keysize']
      dh_params = OpenSSL::PKey::DH.new keysize
      dh_params
    end

    def ask_for_cert_config
      cert_config = {}
      strings_prompt_default = [
        ['C', 'Country Name', 'RU'],
        ['ST', 'State or Province Name', 'MSK'],
        ['L', 'Locality Name', 'Moscow'],
        ['O', 'Organization Name', 'Express 42'],
        ['OU', 'Organizational Unit Name', 'OPS'],
        ['mail', 'Email', 'ops@example.com']
      ]
      numeric_prompt_default = [
        ['rsa_keysize', 'RSA key size (1024/2048/4096)', '2048'],
        ['dh_keysize', 'DH key size (1024/2048/4096)', '1024'],
        ['years_to_expire', 'Expiration (in years from now)', '5']
      ]
      strings_prompt_default.each { |entry| cert_config[entry[0]] = read_with_prompt_and_default(entry[1], entry[2]) }
      numeric_prompt_default.each { |entry| cert_config[entry[0]] = read_with_prompt_and_default(entry[1], entry[2]).to_i }
      %w(rsa_keysize dh_keysize).each do |keysize|
        unless [1024, 2048, 4096].include? cert_config[keysize]
          fail_with "Wrong value for #{keysize}, must be one of 1024/2048/4096"
        end
      end
      cert_config
    end
  end

  class OpenvpnUserCreate < Openvpn
    banner 'knife openvpn user create SERVERNAME USERNAME (options)'

    def run
      check_arguments
      server_name = name_args[0]
      user_name = name_args[1]
      check_existing_databag server_name, false
      check_databag_secret
      create_new_user server_name, user_name
    end

    def create_new_user(server_name, user_name)
      databag_name = get_databag_name server_name
      ca_item = load_databag_item(databag_name, 'openvpn-ca')
      ca_cert, ca_key = load_cert_and_key ca_item['cert'], ca_item['key']
      config_item = load_databag_item(databag_name, 'openvpn-config')
      cert_config = config_item.to_hash
      user_subject = make_name user_name, cert_config
      user_cert, user_key = generate_cert_and_key user_subject, cert_config, false, ca_cert, ca_key, true
      save_databag_item(user_name, server_name, 'cert' => user_cert.to_pem, 'key' => user_key.to_s)
      ui.info "Done, now you can upload #{databag_name}/#{user_name}.json"
    end

    def check_arguments
      unless name_args.size == 2
        fail_with 'Specify SERVERNAME and USERNAME for new openvpn user!'
      end
    end
  end

  class OpenvpnUserExport < Openvpn
    banner 'knife openvpn user export SERVERNAME USERNAME (options)'

    deps do
      require 'chef/search/query'
    end

    def run
      check_arguments
      server_name = name_args[0]
      user_name = name_args[1]
      check_existing_databag server_name, false
      check_databag_secret
      export_user server_name, user_name
    end

    def export_user(server_name, user_name)
      databag_name = get_databag_name server_name
      ca_item = load_databag_item(databag_name, 'openvpn-ca')
      ca_cert, _ca_key = load_cert_and_key ca_item['cert'], ca_item['key']

      ta_key = ''
      begin
        ta_item = load_databag_item(databag_name, 'openvpn-ta')
        ta_key = ta_item['ta']
      rescue Net::HTTPServerException
        ui.warn 'Unable to load openvpn-ta, proceding without it. (Ignore unless you use tls-auth)'
      end

      user_item = load_databag_item(databag_name, user_name)
      user_cert, _user_key = load_cert_and_key user_item['cert'], user_item['key']
      tmpdir = Dir.mktmpdir
      ui.info "tmpdir: #{tmpdir}"
      begin
        user_dir = "#{tmpdir}/#{user_name}-vpn"
        Dir.mkdir user_dir
        ui.info "userdir: #{user_dir}"
        export_file "#{user_dir}/ca.crt", ca_cert.to_pem
        export_file "#{user_dir}/#{user_name}.crt", user_cert.to_pem
        export_file "#{user_dir}/#{user_name}.key", user_item['key'].to_s
        export_file "#{user_dir}/ta.key", ta_key unless ta_key.empty?
        config_content = generate_client_config server_name, user_name
        export_file "#{user_dir}/#{user_name}.ovpn", config_content
        exitcode = system("cd #{tmpdir} && tar cfz /tmp/#{user_name}-vpn.tar.gz *")
        if exitcode
          ui.info "Done, archive at /tmp/#{user_name}-vpn.tar.gz"
        else
          ui.error "Something went wrong, cant create archive at /tmp/#{user_name}-vpn.tar.gz"
        end
      ensure
        FileUtils.rm_rf(tmpdir)
      end
    end

    def export_file(file_path, content)
      File.write file_path, content
      FileUtils.chmod 'u=wr,go-wr', file_path
    end

    def generate_client_config(server_name, user_name)
      query = "openvpn_server_name:#{server_name}"
      query_nodes = Chef::Search::Query.new
      search_result = query_nodes.search('node', query)[0]
      unless search_result.length >= 1
        fail_with "Found #{search_result.length} vpn servers for #{server_name}"
      end
      config_content = ''
      newline = "\n"
      node = search_result[0]
      config = Chef::Mixin::DeepMerge.merge(node['openvpn']['default'].to_hash, node['openvpn'][server_name].to_hash)
      config_content << 'client' << newline
      config_content << "dev  #{config['dev']}" << newline
      config_content << "proto  #{config['proto']}" << newline
      search_result.each do |result|
        config_content << "remote  #{result['openvpn'][server_name]['remote_host']} "
        config_content << "#{config['port']}" << newline
      end
      config_content << "verb  #{config['verb']}" << newline
      config_content << 'comp-lzo' << newline
      config_content << 'ca ca.crt' << newline
      config_content << "cert #{user_name}.crt" << newline
      config_content << "key #{user_name}.key" << newline
      config_content << "tls-auth ta.key 1" << newline if config['use_tls_auth']
      config_content << "ns-cert-type server" << newline
      config_content << 'nobind' << newline
      config_content << 'persist-key' << newline
      config_content << 'persist-tun' << newline
      config_content
    end

    def check_arguments
      unless name_args.size == 2
        fail_with 'Specify SERVERNAME and USERNAME for new openvpn user!'
      end
    end
  end

  class OpenvpnUserRevoke < Openvpn
    banner 'knife openvpn user revoke SERVERNAME USERNAME'

    deps do
      require 'chef/search/query'
    end

    def run
      check_arguments
      server_name = name_args[0]
      user_name = name_args[1]
      check_existing_databag server_name, false
      check_databag_secret
      revoke_user server_name, user_name
    end

    def revoke_user(server_name, user_name)
      now = Time.at(Time.now.to_i)
      databag_name = get_databag_name server_name
      ca_item = load_databag_item(databag_name, 'openvpn-ca')
      ca_cert, ca_key = load_cert_and_key ca_item['cert'], ca_item['key']
      begin
        crl_item = load_databag_item(databag_name, 'openvpn-crl')
        old_crl = OpenSSL::X509::CRL.new crl_item['crl']
        revoke_info = crl_item['revoke_info']
      rescue
        old_crl = issue_crl([], 1, now, now + 3600, [], ca_cert, ca_key, OpenSSL::Digest::SHA256.new)
        revoke_info = []
      end
      user_item = load_databag_item(databag_name, user_name)
      user_cert, _user_key = load_cert_and_key user_item['cert'], user_item['key']
      user_revoke_info = [[user_cert.serial, now, 0]]
      new_revoke_info = revoke_info + user_revoke_info
      new_crl = add_user_to_crl ca_cert, ca_key, old_crl, new_revoke_info
      save_databag_item('openvpn-crl', server_name, 'crl' => new_crl.to_pem, 'revoke_info' => new_revoke_info)
      ui.info "revoked #{user_name}, do not forget to upload CRL databag item"
    end

    def add_user_to_crl(ca_cert, ca_key, old_crl, revoke_info)
      new_crl = issue_crl(revoke_info, old_crl.version + 1, Time.at(Time.now.to_i), Time.at(Time.now.to_i) + 3600, [], ca_cert, ca_key, OpenSSL::Digest::SHA256.new)
      new_crl
    end

    def check_arguments
      unless name_args.size == 2
        fail_with 'Specify SERVERNAME and USERNAME for existing openvpn user!'
      end
    end
  end
end
